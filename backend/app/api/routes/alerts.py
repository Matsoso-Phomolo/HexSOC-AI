from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.schemas.alert import AlertCreate, AlertRead, AlertStatusUpdate
from app.services.activity_service import add_activity

router = APIRouter()


@router.post("/", response_model=AlertRead, status_code=201, summary="Create alert")
def create_alert(payload: AlertCreate, db: Session = Depends(get_db)) -> models.Alert:
    """Store an analyst-facing alert."""
    alert = models.Alert(**payload.dict())
    db.add(alert)
    db.flush()
    add_activity(
        db,
        action="alert_created",
        entity_type="alert",
        entity_id=alert.id,
        message=f"Alert created: {alert.title}",
        severity=alert.severity,
    )
    db.commit()
    db.refresh(alert)
    return alert


@router.get("/", response_model=list[AlertRead], summary="List alerts")
def list_alerts(db: Session = Depends(get_db)) -> list[models.Alert]:
    """Return stored alerts ordered by newest first."""
    return db.query(models.Alert).order_by(models.Alert.id.desc()).all()


@router.patch("/{alert_id}/status", response_model=AlertRead, summary="Update alert status")
def update_alert_status(
    alert_id: int,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
) -> models.Alert:
    """Update the lifecycle status for an alert."""
    alert = db.get(models.Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    previous_status = alert.status
    alert.status = payload.status
    add_activity(
        db,
        action="alert_status_changed",
        entity_type="alert",
        entity_id=alert.id,
        message=f"Alert status changed from {previous_status} to {alert.status}",
        severity=alert.severity,
    )
    db.commit()
    db.refresh(alert)
    return alert
