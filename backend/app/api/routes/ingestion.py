"""Log ingestion API for external telemetry sources."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.schemas.ingestion import BulkIngestRequest, BulkIngestResponse, IngestLogItem
from app.services.auth_service import require_role
from app.services.detection_engine import run_detection_rules
from app.services.log_ingestion_service import ingest_logs
from app.services.websocket_manager import serialize_activity, websocket_manager

router = APIRouter()


@router.post("/events", response_model=BulkIngestResponse, status_code=201, summary="Ingest one log event")
async def ingest_event(
    payload: IngestLogItem,
    auto_detect: bool = Query(default=False),
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> BulkIngestResponse:
    """Ingest a single normalized log event."""
    return await _ingest([payload], auto_detect=auto_detect, db=db, user=user)


@router.post("/events/bulk", response_model=BulkIngestResponse, status_code=201, summary="Bulk ingest log events")
async def ingest_events_bulk(
    payload: BulkIngestRequest,
    auto_detect: bool = Query(default=False),
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> BulkIngestResponse:
    """Ingest a batch of normalized log events."""
    return await _ingest(payload.logs, auto_detect=auto_detect, db=db, user=user)


async def _ingest(
    logs: list[IngestLogItem],
    *,
    auto_detect: bool,
    db: Session,
    user: models.User,
    event_type: str = "event_ingested",
    bulk_event_type: str = "bulk_ingestion_completed",
    activity_action: str | None = None,
    activity_message: str | None = None,
) -> BulkIngestResponse:
    result = ingest_logs(
        db,
        logs,
        actor_username=user.username,
        actor_role=user.role,
        activity_action=activity_action,
        activity_message=activity_message,
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

    await websocket_manager.broadcast_activity(
        {
            "type": event_type if len(logs) == 1 else bulk_event_type,
            "received": result["received"],
            "ingested": result["ingested"],
            "assets_created": result["assets_created"],
            "auto_detect": auto_detect,
        }
    )
    await websocket_manager.broadcast_activity({"type": "activity_created", "activity": serialize_activity(activity)})
    await websocket_manager.broadcast_activity({"type": "graph_updated"})

    return BulkIngestResponse(
        **result,
        detections_run=bool(auto_detect and result["ingested"]),
        detection_summary=detection_summary,
    )
