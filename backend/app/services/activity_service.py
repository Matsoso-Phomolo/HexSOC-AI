from sqlalchemy.orm import Session

from app.db import models


def add_activity(
    db: Session,
    *,
    action: str,
    entity_type: str,
    entity_id: int | None,
    message: str,
    severity: str = "info",
) -> models.ActivityLog:
    """Stage a SOC activity timeline entry in the current transaction."""
    activity = models.ActivityLog(
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        message=message,
        severity=severity,
    )
    db.add(activity)
    return activity
