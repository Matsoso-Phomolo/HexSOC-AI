from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.schemas.event import EventCreate, EventRead

router = APIRouter()


@router.post("/", response_model=EventRead, status_code=201, summary="Create security event")
def create_event(payload: EventCreate, db: Session = Depends(get_db)) -> models.SecurityEvent:
    """Store a normalized security event."""
    event = models.SecurityEvent(**payload.dict())
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


@router.get("/", response_model=list[EventRead], summary="List security events")
def list_events(db: Session = Depends(get_db)) -> list[models.SecurityEvent]:
    """Return stored security events ordered by newest first."""
    return db.query(models.SecurityEvent).order_by(models.SecurityEvent.id.desc()).all()
