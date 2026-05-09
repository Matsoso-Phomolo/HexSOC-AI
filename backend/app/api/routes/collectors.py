"""Collector management and API-key authenticated ingestion routes."""

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.schemas.collector import (
    CollectorCreate,
    CollectorCreatedResponse,
    CollectorRead,
    CollectorRotateResponse,
    CollectorUpdate,
)
from app.schemas.ingestion import BulkIngestRequest, BulkIngestResponse, IngestLogItem
from app.services.activity_service import add_activity
from app.services.auth_service import require_role
from app.services.collector_service import (
    create_collector,
    get_collector_from_key,
    revoke_collector,
    rotate_collector_key,
)
from app.services.detection_engine import run_detection_rules
from app.services.log_ingestion_service import ingest_logs
from app.services.websocket_manager import serialize_activity, websocket_manager
from app.services.windows_event_parser import parse_windows_event, parse_windows_events

router = APIRouter()


@router.post("/ingest/event", response_model=BulkIngestResponse, status_code=201, summary="Collector ingest event")
async def collector_ingest_event(
    payload: IngestLogItem,
    auto_detect: bool = Query(default=False),
    api_key: str | None = Header(default=None, alias="X-HexSOC-API-Key"),
    db: Session = Depends(get_db),
) -> BulkIngestResponse:
    collector = get_collector_from_key(db, api_key)
    return await _collector_ingest([payload], collector=collector, auto_detect=auto_detect, db=db)


@router.post("/ingest/events/bulk", response_model=BulkIngestResponse, status_code=201, summary="Collector bulk ingest events")
async def collector_ingest_events_bulk(
    payload: BulkIngestRequest,
    auto_detect: bool = Query(default=False),
    api_key: str | None = Header(default=None, alias="X-HexSOC-API-Key"),
    db: Session = Depends(get_db),
) -> BulkIngestResponse:
    collector = get_collector_from_key(db, api_key)
    return await _collector_ingest(payload.logs, collector=collector, auto_detect=auto_detect, db=db)


@router.post("/ingest/windows-event", response_model=BulkIngestResponse, status_code=201, summary="Collector ingest Windows event")
async def collector_ingest_windows_event(
    payload: dict[str, Any],
    auto_detect: bool = Query(default=False),
    api_key: str | None = Header(default=None, alias="X-HexSOC-API-Key"),
    db: Session = Depends(get_db),
) -> BulkIngestResponse:
    collector = get_collector_from_key(db, api_key)
    return await _collector_ingest([parse_windows_event(payload)], collector=collector, auto_detect=auto_detect, db=db)


@router.post("/ingest/windows-events/bulk", response_model=BulkIngestResponse, status_code=201, summary="Collector bulk ingest Windows events")
async def collector_ingest_windows_events_bulk(
    payload: dict[str, Any] | list[dict[str, Any]],
    auto_detect: bool = Query(default=False),
    api_key: str | None = Header(default=None, alias="X-HexSOC-API-Key"),
    db: Session = Depends(get_db),
) -> BulkIngestResponse:
    collector = get_collector_from_key(db, api_key)
    raw_events = payload.get("events") if isinstance(payload, dict) else payload
    raw_events = raw_events or payload.get("logs") if isinstance(payload, dict) else raw_events
    parsed, parse_errors = parse_windows_events(raw_events if isinstance(raw_events, list) else [])
    response = await _collector_ingest(parsed, collector=collector, auto_detect=auto_detect, db=db)
    response.received = len(raw_events) if isinstance(raw_events, list) else 0
    response.skipped += len(parse_errors)
    response.validation_errors.extend(parse_errors)
    return response


@router.get("/", response_model=list[CollectorRead], summary="List collectors")
def list_collectors(
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("analyst")),
) -> list[models.Collector]:
    return db.query(models.Collector).order_by(models.Collector.id.desc()).all()


@router.post("/", response_model=CollectorCreatedResponse, status_code=201, summary="Create collector")
async def create_live_collector(
    payload: CollectorCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> CollectorCreatedResponse:
    collector, api_key = create_collector(db, payload, created_by=user.username)
    activity = add_activity(
        db,
        action="collector_created",
        entity_type="collector",
        entity_id=collector.id,
        message=f"Collector created: {collector.name}",
        severity="info",
        actor_username=user.username,
        actor_role=user.role,
    )
    db.commit()
    db.refresh(collector)
    db.refresh(activity)
    await _broadcast_collector("collector_created", collector, activity)
    return CollectorCreatedResponse(collector=collector, api_key=api_key)


@router.patch("/{collector_id}", response_model=CollectorRead, summary="Update collector")
async def update_collector(
    collector_id: int,
    payload: CollectorUpdate,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> models.Collector:
    collector = _get_collector_or_404(db, collector_id)
    if payload.name is not None:
        collector.name = payload.name.strip()
    if payload.description is not None:
        collector.description = payload.description
    if payload.collector_type is not None:
        collector.collector_type = payload.collector_type.strip()
    if payload.source_label is not None:
        collector.source_label = payload.source_label.strip() or None
    if payload.is_active is not None:
        collector.is_active = payload.is_active
    activity = add_activity(
        db,
        action="collector_updated",
        entity_type="collector",
        entity_id=collector.id,
        message=f"Collector updated: {collector.name}",
        severity="info",
        actor_username=user.username,
        actor_role=user.role,
    )
    db.commit()
    db.refresh(collector)
    db.refresh(activity)
    await _broadcast_collector("collector_updated", collector, activity)
    return collector


@router.post("/{collector_id}/rotate", response_model=CollectorRotateResponse, summary="Rotate collector key")
async def rotate_live_collector(
    collector_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("admin")),
) -> CollectorRotateResponse:
    collector = _get_collector_or_404(db, collector_id)
    collector, api_key = rotate_collector_key(db, collector)
    activity = add_activity(
        db,
        action="collector_rotated",
        entity_type="collector",
        entity_id=collector.id,
        message=f"Collector key rotated: {collector.name}",
        severity="warning",
        actor_username=user.username,
        actor_role=user.role,
    )
    db.commit()
    db.refresh(collector)
    db.refresh(activity)
    await _broadcast_collector("collector_updated", collector, activity)
    return CollectorRotateResponse(collector=collector, api_key=api_key)


@router.post("/{collector_id}/revoke", response_model=CollectorRead, summary="Revoke collector")
async def revoke_live_collector(
    collector_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("admin")),
) -> models.Collector:
    collector = revoke_collector(db, _get_collector_or_404(db, collector_id))
    activity = add_activity(
        db,
        action="collector_revoked",
        entity_type="collector",
        entity_id=collector.id,
        message=f"Collector revoked: {collector.name}",
        severity="warning",
        actor_username=user.username,
        actor_role=user.role,
    )
    db.commit()
    db.refresh(collector)
    db.refresh(activity)
    await _broadcast_collector("collector_revoked", collector, activity)
    return collector


async def _collector_ingest(
    logs: list[IngestLogItem],
    *,
    collector: models.Collector,
    auto_detect: bool,
    db: Session,
) -> BulkIngestResponse:
    tagged_logs = [_tag_log(log, collector) for log in logs]
    result = ingest_logs(
        db,
        tagged_logs,
        actor_username=collector.name,
        actor_role="collector",
        activity_action="collector_bulk_ingestion_completed" if len(tagged_logs) > 1 else "collector_event_ingested",
        activity_message=f"Collector {collector.name} ingested {len(tagged_logs)} event(s).",
    )
    activity = result.pop("_activity")
    detection_summary: dict[str, int] | None = None
    if auto_detect and result["ingested"]:
        detection_result = run_detection_rules(db)
        created_alerts = detection_result.pop("_created_alerts", [])
        created_activities = detection_result.pop("_created_activities", [])
        detection_summary = {
            "rules_checked": int(detection_result["rules_checked"]),
            "alerts_created": int(detection_result["alerts_created"]),
            "matches_found": int(detection_result["matches_found"]),
        }
        for alert in created_alerts:
            await websocket_manager.broadcast_alert({"type": "alert_created", "alert": alert})
        for detection_activity in created_activities:
            await websocket_manager.broadcast_activity({"type": "activity_created", "activity": detection_activity})

    await websocket_manager.broadcast_activity({"type": "activity_created", "activity": serialize_activity(activity)})
    await websocket_manager.broadcast_activity(
        {
            "type": "collector_ingestion_completed",
            "collector_id": collector.id,
            "collector_name": collector.name,
            "ingested": result["ingested"],
            "auto_detect": auto_detect,
        }
    )
    await websocket_manager.broadcast_activity({"type": "graph_updated"})
    return BulkIngestResponse(
        **result,
        detections_run=bool(auto_detect and result["ingested"]),
        detection_summary=detection_summary,
    )


def _tag_log(log: IngestLogItem, collector: models.Collector) -> IngestLogItem:
    raw_payload = dict(log.raw_payload or {})
    raw_payload.update(
        {
            "collector_id": collector.id,
            "collector_name": collector.name,
            "collector_type": collector.collector_type,
        }
    )
    return log.model_copy(
        update={
            "source": collector.source_label or collector.name,
            "raw_payload": raw_payload,
        }
    )


def _get_collector_or_404(db: Session, collector_id: int) -> models.Collector:
    collector = db.get(models.Collector, collector_id)
    if collector is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Collector not found")
    return collector


async def _broadcast_collector(event_type: str, collector: models.Collector, activity: models.ActivityLog) -> None:
    await websocket_manager.broadcast_activity({"type": "activity_created", "activity": serialize_activity(activity)})
    await websocket_manager.broadcast_activity(
        {
            "type": event_type,
            "collector_id": collector.id,
            "collector_name": collector.name,
            "is_active": collector.is_active,
        }
    )
