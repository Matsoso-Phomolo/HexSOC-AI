from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.schemas.alert import AlertCreate, AlertRead, AlertStatusUpdate
from app.services.activity_service import add_activity
from app.services.auth_service import require_role
from app.services.websocket_manager import serialize_activity, serialize_alert, websocket_manager

router = APIRouter()


@router.post("/", response_model=AlertRead, status_code=201, summary="Create alert")
async def create_alert(
    payload: AlertCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> models.Alert:
    """Store an analyst-facing alert."""
    alert = models.Alert(**payload.dict())
    db.add(alert)
    db.flush()
    activity = add_activity(
        db,
        action="alert_created",
        entity_type="alert",
        entity_id=alert.id,
        message=f"Alert created: {alert.title}",
        severity=alert.severity,
    )
    db.commit()
    db.refresh(alert)
    db.refresh(activity)
    await websocket_manager.broadcast_alert({"type": "alert_created", "alert": serialize_alert(alert)})
    await websocket_manager.broadcast_activity(
        {"type": "activity_created", "activity": serialize_activity(activity)}
    )
    return alert


@router.get("/", response_model=list[AlertRead], summary="List alerts")
def list_alerts(db: Session = Depends(get_db)) -> list[models.Alert]:
    """Return stored alerts ordered by newest first."""
    return db.query(models.Alert).order_by(models.Alert.id.desc()).all()


@router.patch("/{alert_id}/status", response_model=AlertRead, summary="Update alert status")
async def update_alert_status(
    alert_id: int,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> models.Alert:
    """Update the lifecycle status for an alert."""
    alert = db.get(models.Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    previous_status = alert.status
    alert.status = payload.status
    activity = add_activity(
        db,
        action="alert_status_changed",
        entity_type="alert",
        entity_id=alert.id,
        message=f"Alert status changed from {previous_status} to {alert.status}",
        severity=alert.severity,
    )
    db.commit()
    db.refresh(alert)
    db.refresh(activity)
    await websocket_manager.broadcast_alert(
        {
            "type": "alert_status_changed",
            "alert_id": alert.id,
            "status": alert.status,
            "alert": serialize_alert(alert),
        }
    )
    await websocket_manager.broadcast_activity(
        {"type": "activity_created", "activity": serialize_activity(activity)}
    )
    return alert
