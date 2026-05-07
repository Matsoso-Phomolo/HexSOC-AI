from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.schemas.activity import ActivityRead

router = APIRouter()


@router.get("/", response_model=list[ActivityRead], summary="List SOC activity")
def list_activity(db: Session = Depends(get_db)) -> list[models.ActivityLog]:
    """Return the full SOC activity timeline ordered newest first."""
    return db.query(models.ActivityLog).order_by(models.ActivityLog.id.desc()).all()


@router.get("/recent", response_model=list[ActivityRead], summary="List recent SOC activity")
def recent_activity(limit: int = 20, db: Session = Depends(get_db)) -> list[models.ActivityLog]:
    """Return recent SOC activity entries ordered newest first."""
    safe_limit = min(max(limit, 1), 100)
    return (
        db.query(models.ActivityLog)
        .order_by(models.ActivityLog.id.desc())
        .limit(safe_limit)
        .all()
    )
