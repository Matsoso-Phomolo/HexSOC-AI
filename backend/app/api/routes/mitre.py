"""MITRE ATT&CK mapping endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.services.activity_service import add_activity
from app.services.auth_service import require_role
from app.services.mitre_mapping_service import coverage_summary, map_unmapped_alerts, map_unmapped_events
from app.services.websocket_manager import serialize_activity, websocket_manager

router = APIRouter()


@router.post("/map-events", summary="Map existing events to MITRE")
async def map_events(
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> dict[str, int]:
    """Backfill MITRE mappings for unmapped security events."""
    mapped = map_unmapped_events(db)
    activity = add_activity(
        db,
        action="mitre_events_mapped",
        entity_type="mitre",
        entity_id=None,
        message=f"MITRE mapping completed for {mapped} security events.",
        severity="info",
        actor_username=user.username,
        actor_role=user.role,
    )
    db.commit()
    db.refresh(activity)
    await _broadcast(activity, db)
    return {"mapped_events": mapped}


@router.post("/map-alerts", summary="Map existing alerts to MITRE")
async def map_alerts(
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> dict[str, int]:
    """Backfill MITRE mappings for unmapped alerts."""
    mapped = map_unmapped_alerts(db)
    activity = add_activity(
        db,
        action="mitre_alerts_mapped",
        entity_type="mitre",
        entity_id=None,
        message=f"MITRE mapping completed for {mapped} alerts.",
        severity="info",
        actor_username=user.username,
        actor_role=user.role,
    )
    db.commit()
    db.refresh(activity)
    await _broadcast(activity, db)
    return {"mapped_alerts": mapped}


@router.get("/coverage", summary="Get MITRE coverage")
def get_coverage(
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("viewer")),
) -> dict:
    """Return MITRE mapping coverage across events and alerts."""
    return coverage_summary(db)


async def _broadcast(activity: models.ActivityLog, db: Session) -> None:
    await websocket_manager.broadcast_activity({"type": "activity_created", "activity": serialize_activity(activity)})
    await websocket_manager.broadcast_activity({"type": "mitre_mapping_completed"})
    await websocket_manager.broadcast_activity({"type": "graph_updated"})
    await websocket_manager.broadcast_dashboard_metrics(db)
