from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.schemas.incident import IncidentCreate, IncidentRead, IncidentStatusUpdate
from app.services.activity_service import add_activity

router = APIRouter()


@router.post("/", response_model=IncidentRead, status_code=201, summary="Create incident")
def create_incident(payload: IncidentCreate, db: Session = Depends(get_db)) -> models.Incident:
    """Store an incident case for security response."""
    incident = models.Incident(**payload.dict())
    db.add(incident)
    db.flush()
    add_activity(
        db,
        action="incident_created",
        entity_type="incident",
        entity_id=incident.id,
        message=f"Incident created: {incident.title}",
        severity=incident.severity,
    )
    db.commit()
    db.refresh(incident)
    return incident


@router.get("/", response_model=list[IncidentRead], summary="List incidents")
def list_incidents(db: Session = Depends(get_db)) -> list[models.Incident]:
    """Return stored incidents ordered by newest first."""
    return db.query(models.Incident).order_by(models.Incident.id.desc()).all()


@router.patch("/{incident_id}/status", response_model=IncidentRead, summary="Update incident status")
def update_incident_status(
    incident_id: int,
    payload: IncidentStatusUpdate,
    db: Session = Depends(get_db),
) -> models.Incident:
    """Update the lifecycle status for an incident."""
    incident = db.get(models.Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    previous_status = incident.status
    incident.status = payload.status
    add_activity(
        db,
        action="incident_status_changed",
        entity_type="incident",
        entity_id=incident.id,
        message=f"Incident status changed from {previous_status} to {incident.status}",
        severity=incident.severity or "info",
    )
    db.commit()
    db.refresh(incident)
    return incident
