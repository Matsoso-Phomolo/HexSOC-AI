from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.schemas.incident import IncidentCreate, IncidentRead

router = APIRouter()


@router.post("/", response_model=IncidentRead, status_code=201, summary="Create incident")
def create_incident(payload: IncidentCreate, db: Session = Depends(get_db)) -> models.Incident:
    """Store an incident case for security response."""
    incident = models.Incident(**payload.dict())
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


@router.get("/", response_model=list[IncidentRead], summary="List incidents")
def list_incidents(db: Session = Depends(get_db)) -> list[models.Incident]:
    """Return stored incidents ordered by newest first."""
    return db.query(models.Incident).order_by(models.Incident.id.desc()).all()
