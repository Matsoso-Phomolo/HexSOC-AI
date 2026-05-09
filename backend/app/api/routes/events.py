from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.schemas.event import EventCreate, EventRead
from app.services.activity_service import add_activity
from app.services.websocket_manager import serialize_activity, websocket_manager

router = APIRouter()


@router.post("/", response_model=EventRead, status_code=201, summary="Create security event")
async def create_event(payload: EventCreate, db: Session = Depends(get_db)) -> models.SecurityEvent:
    """Store a normalized security event."""
    event = models.SecurityEvent(**payload.dict())
    db.add(event)
    db.flush()
    activity = add_activity(
        db,
        action="event_created",
        entity_type="security_event",
        entity_id=event.id,
        message=f"Security event created: {event.event_type} from {event.source}",
        severity=event.severity,
    )
    db.commit()
    db.refresh(event)
    db.refresh(activity)
    await websocket_manager.broadcast_activity(
        {"type": "activity_created", "activity": serialize_activity(activity)}
    )
    await websocket_manager.broadcast_event("event_ingested", {"event_id": event.id, "event_type": event.event_type})
    await websocket_manager.broadcast_dashboard_metrics(db)
    return event


@router.get("/", response_model=list[EventRead], summary="List security events")
def list_events(db: Session = Depends(get_db)) -> list[models.SecurityEvent]:
    """Return stored security events ordered by newest first."""
    return db.query(models.SecurityEvent).order_by(models.SecurityEvent.id.desc()).all()
