"""Collector management and API-key authenticated ingestion routes."""

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.security.permissions import Permission, require_permission
from app.schemas.collector import (
    CollectorCreate,
    CollectorCreatedResponse,
    CollectorFleetDetail,
    CollectorFleetSummary,
    CollectorHealthSummary,
    CollectorHeartbeatRequest,
    CollectorHeartbeatResponse,
    CollectorRead,
    CollectorRotateResponse,
    CollectorUpdate,
)
from app.schemas.ingestion import BulkIngestRequest, BulkIngestResponse, IngestLogItem
from app.services.activity_service import add_activity
from app.services.audit_log_service import log_success
from app.services.collector_service import (
    calculate_health_status,
    create_collector,
    get_collector_from_key,
    refresh_collector_health,
    revoke_collector,
    rotate_collector_key,
)
from app.services.collector_fleet_service import (
    collector_detail,
    offline_collectors,
    summarize_fleet,
    version_drift_collectors,
)
from app.services.detection_engine import run_detection_rules
from app.services.log_ingestion_service import ingest_logs
from app.services.notification_service import send_notification
from app.services.websocket_manager import serialize_activity, serialize_collector, websocket_manager
from app.services.windows_event_parser import parse_windows_event, parse_windows_events

router = APIRouter()


@router.post("/heartbeat", response_model=CollectorHeartbeatResponse, summary="Collector heartbeat")
async def collector_heartbeat(
    payload: CollectorHeartbeatRequest | None = None,
    api_key: str | None = Header(default=None, alias="X-HexSOC-API-Key"),
    db: Session = Depends(get_db),
) -> CollectorHeartbeatResponse:
    collector = get_collector_from_key(db, api_key)
    heartbeat = payload or CollectorHeartbeatRequest()
    previous_status = collector.health_status or "offline"
    now = datetime.now(timezone.utc)
    collector.last_seen_at = now
    collector.last_heartbeat_at = now
    collector.heartbeat_count = (collector.heartbeat_count or 0) + 1
    collector.health_status = "online"
    if heartbeat.agent_version is not None:
        collector.agent_version = heartbeat.agent_version
    if heartbeat.host_name is not None:
        collector.host_name = heartbeat.host_name
    if heartbeat.os_name is not None:
        collector.os_name = heartbeat.os_name
    if heartbeat.os_version is not None:
        collector.os_version = heartbeat.os_version
    if heartbeat.last_event_count is not None:
        collector.last_event_count = heartbeat.last_event_count
    if "last_error" in heartbeat.model_fields_set:
        collector.last_error = heartbeat.last_error
    activity = add_activity(
        db,
        action="collector_heartbeat_received",
        entity_type="collector",
        entity_id=collector.id,
        message=f"Heartbeat received from collector {collector.name}.",
        severity="info",
        actor_username=collector.name,
        actor_role="collector",
    )
    status_activity = None
    if previous_status != collector.health_status:
        status_activity = add_activity(
            db,
            action="collector_health_changed",
            entity_type="collector",
            entity_id=collector.id,
            message=f"Collector {collector.name} changed health from {previous_status} to {collector.health_status}.",
            severity="warning" if collector.health_status in {"stale", "offline"} else "info",
            actor_username=collector.name,
            actor_role="collector",
        )
    db.commit()
    db.refresh(collector)
    db.refresh(activity)
    if status_activity is not None:
        db.refresh(status_activity)
    await websocket_manager.broadcast_activity({"type": "activity_created", "activity": serialize_activity(activity)})
    if status_activity is not None:
        await websocket_manager.broadcast_activity(
            {"type": "activity_created", "activity": serialize_activity(status_activity)}
        )
    await websocket_manager.broadcast_activity(
        {
            "type": "collector_heartbeat",
            "collector": serialize_collector(collector),
        }
    )
    if previous_status != collector.health_status:
        await websocket_manager.broadcast_activity(
            {
                "type": "collector_health_changed",
                "collector": serialize_collector(collector),
                "previous_status": previous_status,
                "health_status": collector.health_status,
            }
        )
    await websocket_manager.broadcast_dashboard_metrics(db)
    return CollectorHeartbeatResponse(
        collector_name=collector.name,
        collector_type=collector.collector_type,
        status="online",
        last_seen_at=collector.last_seen_at,
        last_heartbeat_at=collector.last_heartbeat_at,
        heartbeat_count=collector.heartbeat_count or 0,
        health_status=collector.health_status,
    )


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
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_permission(Permission.COLLECTOR_READ)),
) -> list[models.Collector]:
    collectors = db.query(models.Collector).order_by(models.Collector.id.desc()).limit(limit).all()
    _refresh_health_batch(db, collectors)
    return collectors


@router.get("/health", response_model=CollectorHealthSummary, summary="Collector fleet health")
def collector_health(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_permission(Permission.COLLECTOR_READ)),
) -> CollectorHealthSummary:
    collectors = db.query(models.Collector).order_by(models.Collector.id.desc()).limit(limit).all()
    _refresh_health_batch(db, collectors)
    counts = {"online": 0, "degraded": 0, "stale": 0, "offline": 0, "revoked": 0}
    for collector in collectors:
        status_key = collector.health_status or calculate_health_status(collector)
        status_key = "degraded" if status_key == "online" and collector.last_error else status_key
        counts[status_key if status_key in counts else "offline"] += 1
    return CollectorHealthSummary(
        total_collectors=len(collectors),
        online=counts["online"],
        degraded=counts["degraded"],
        stale=counts["stale"],
        offline=counts["offline"],
        revoked=counts["revoked"],
        collectors=collectors,
    )


@router.get("/fleet/summary", response_model=CollectorFleetSummary, summary="Collector fleet summary")
def collector_fleet_summary(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_permission(Permission.COLLECTOR_READ)),
) -> dict:
    return summarize_fleet(db, limit=limit)


@router.get("/fleet/health", response_model=CollectorFleetSummary, summary="Collector fleet health summary")
def collector_fleet_health(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_permission(Permission.COLLECTOR_READ)),
) -> dict:
    return summarize_fleet(db, limit=limit)


@router.get("/fleet/offline", response_model=list[CollectorRead], summary="Offline or stale collectors")
def collector_fleet_offline(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_permission(Permission.COLLECTOR_READ)),
) -> list[models.Collector]:
    return offline_collectors(db, limit=limit)


@router.get("/fleet/version-drift", response_model=list[CollectorRead], summary="Collectors with version drift")
def collector_fleet_version_drift(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_permission(Permission.COLLECTOR_READ)),
) -> list[models.Collector]:
    return version_drift_collectors(db, limit=limit)


@router.get("/fleet/{collector_id}", response_model=CollectorFleetDetail, summary="Collector fleet detail")
def collector_fleet_detail(
    collector_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_permission(Permission.COLLECTOR_READ)),
) -> dict:
    detail = collector_detail(db, collector_id)
    if detail is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Collector not found")
    return detail


@router.post("/", response_model=CollectorCreatedResponse, status_code=201, summary="Create collector")
async def create_live_collector(
    payload: CollectorCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_permission(Permission.COLLECTOR_CREATE)),
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
    log_success(
        db,
        action="collector_created",
        category="collector",
        actor=user,
        request=request,
        target_type="collector",
        target_id=collector.id,
        target_label=collector.name,
        metadata={"collector_type": collector.collector_type, "source_label": collector.source_label},
    )
    db.commit()
    await _broadcast_collector("collector_created", collector, activity)
    await websocket_manager.broadcast_dashboard_metrics(db)
    return CollectorCreatedResponse(collector=collector, api_key=api_key)


@router.patch("/{collector_id}", response_model=CollectorRead, summary="Update collector")
async def update_collector(
    collector_id: int,
    payload: CollectorUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_permission(Permission.COLLECTOR_MANAGE)),
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
    log_success(
        db,
        action="collector_updated",
        category="collector",
        actor=user,
        request=request,
        target_type="collector",
        target_id=collector.id,
        target_label=collector.name,
        metadata={"updated_fields": [key for key, value in payload.model_dump().items() if value is not None]},
    )
    db.commit()
    await _broadcast_collector("collector_updated", collector, activity)
    await websocket_manager.broadcast_dashboard_metrics(db)
    return collector


@router.post("/{collector_id}/rotate", response_model=CollectorRotateResponse, summary="Rotate collector key")
async def rotate_live_collector(
    collector_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_permission(Permission.COLLECTOR_MANAGE)),
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
    log_success(
        db,
        action="collector_rotated",
        category="collector",
        actor=user,
        request=request,
        target_type="collector",
        target_id=collector.id,
        target_label=collector.name,
        metadata={"key_prefix": collector.key_prefix},
    )
    db.commit()
    await _broadcast_collector("collector_updated", collector, activity)
    await websocket_manager.broadcast_dashboard_metrics(db)
    return CollectorRotateResponse(collector=collector, api_key=api_key)


@router.post("/{collector_id}/revoke", response_model=CollectorRead, summary="Revoke collector")
async def revoke_live_collector(
    collector_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_permission(Permission.COLLECTOR_MANAGE)),
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
    log_success(
        db,
        action="collector_revoked",
        category="collector",
        actor=user,
        request=request,
        target_type="collector",
        target_id=collector.id,
        target_label=collector.name,
        metadata={"collector_type": collector.collector_type},
    )
    db.commit()
    await _broadcast_collector("collector_revoked", collector, activity)
    await websocket_manager.broadcast_dashboard_metrics(db)
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
    collector.last_event_count = result["ingested"]
    collector.last_error = None if result["skipped"] == 0 else f"{result['skipped']} event(s) skipped"
    db.add(collector)
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
    await websocket_manager.broadcast_event(
        "event_ingested",
        {
            "collector": serialize_collector(collector),
            "ingested": result["ingested"],
            "assets_created": result["assets_created"],
        },
    )
    await websocket_manager.broadcast_activity(
        {
            "type": "collector_ingestion_completed",
            "collector": serialize_collector(collector),
            "ingested": result["ingested"],
            "auto_detect": auto_detect,
        }
    )
    await websocket_manager.broadcast_activity({"type": "graph_updated"})
    await websocket_manager.broadcast_dashboard_metrics(db)
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


def _refresh_health_batch(db: Session, collectors: list[models.Collector]) -> None:
    changed = False
    now = datetime.now(timezone.utc)
    for collector in collectors:
        old_status, new_status = refresh_collector_health(collector, now=now)
        if old_status != new_status:
            changed = True
            add_activity(
                db,
                action="collector_health_changed",
                entity_type="collector",
                entity_id=collector.id,
                message=f"Collector {collector.name} changed health from {old_status} to {new_status}.",
                severity="warning" if new_status in {"stale", "offline"} else "info",
                actor_username="system",
                actor_role="system",
            )
            if new_status in {"offline", "stale"}:
                send_notification(
                    db,
                    event_type="collector_offline" if new_status == "offline" else "collector_degraded",
                    title=f"Collector {new_status}: {collector.name}",
                    message=f"Collector {collector.name} changed health from {old_status} to {new_status}.",
                    severity="warning",
                    metadata={
                        "collector_id": collector.id,
                        "collector_type": collector.collector_type,
                        "source_label": collector.source_label,
                        "previous_status": old_status,
                        "health_status": new_status,
                    },
                )
            db.add(collector)
    if changed:
        db.commit()


async def _broadcast_collector(event_type: str, collector: models.Collector, activity: models.ActivityLog) -> None:
    await websocket_manager.broadcast_activity({"type": "activity_created", "activity": serialize_activity(activity)})
    await websocket_manager.broadcast_activity(
        {
            "type": event_type,
            "collector": serialize_collector(collector),
        }
    )
