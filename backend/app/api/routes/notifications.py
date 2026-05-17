"""Notification integration status and log routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.security.permissions import Permission, require_permission
from app.services.audit_log_service import log_success
from app.services.notification_service import (
    notification_summary,
    notification_status,
    send_notification,
    serialize_notification_log,
)

router = APIRouter()


@router.get("/logs", summary="List notification logs")
def list_notification_logs(
    event_type: str | None = Query(default=None, max_length=120),
    outcome: str | None = Query(default=None, max_length=40),
    channel: str | None = Query(default=None, max_length=80),
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_permission(Permission.AUDIT_READ)),
) -> dict[str, Any]:
    """Return bounded notification delivery logs."""
    query = db.query(models.NotificationLog)
    if event_type:
        query = query.filter(models.NotificationLog.event_type == event_type.strip())
    if outcome:
        query = query.filter(models.NotificationLog.outcome == outcome.strip())
    if channel:
        query = query.filter(models.NotificationLog.channel == channel.strip())
    logs = query.order_by(models.NotificationLog.id.desc()).limit(limit).all()
    return {"total": len(logs), "limit": limit, "logs": [serialize_notification_log(log) for log in logs]}


@router.get("/summary", summary="Notification integration summary")
def get_notification_summary(
    db: Session = Depends(get_db),
    _: models.User = Depends(require_permission(Permission.AUDIT_READ)),
) -> dict[str, Any]:
    """Return notification provider status and compact log summary."""
    return notification_summary(db)


@router.post("/test", summary="Send test notification")
def send_test_notification(
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_permission(Permission.AUDIT_READ)),
) -> dict[str, Any]:
    """Send a bounded test notification through configured providers."""
    logs = send_notification(
        db,
        event_type="test_notification",
        title="HexSOC AI test notification",
        message="Notification integration test requested from the SOC dashboard.",
        severity="info",
        metadata={"requested_by": user.username},
    )
    log_success(
        db,
        action="notification_test_requested",
        category="system",
        actor=user,
        request=request,
        target_type="notification",
        target_label="test_notification",
        metadata=notification_status(),
    )
    db.commit()
    return {"sent": any(log.outcome == "success" for log in logs), "logs": [serialize_notification_log(log) for log in logs]}
