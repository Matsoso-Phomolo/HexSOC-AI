"""Safe notification integration foundation for high-value SOC events."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db import models
from app.services.audit_log_service import sanitize_metadata

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 8
MAX_METADATA_ITEMS = 50


def send_notification(
    db: Session,
    *,
    event_type: str,
    title: str,
    message: str,
    severity: str = "info",
    metadata: dict[str, Any] | None = None,
) -> list[models.NotificationLog]:
    """Send configured notifications without breaking the caller workflow."""
    sanitized = _notification_payload(event_type, title, message, severity, metadata or {})
    logs: list[models.NotificationLog] = []

    if not settings.notifications_enabled:
        logs.append(_add_log(db, event_type=event_type, channel="system", target=None, outcome="skipped", metadata={**sanitized, "reason": "notifications_disabled"}))
        return logs

    if _is_rate_limited(db, event_type):
        logs.append(_add_log(db, event_type=event_type, channel="system", target=None, outcome="skipped", metadata={**sanitized, "reason": "rate_limited"}))
        return logs

    if settings.notification_webhook_url:
        logs.append(send_webhook_notification(db, sanitized))
    else:
        logs.append(_add_log(db, event_type=event_type, channel="webhook", target="configured:false", outcome="skipped", metadata={**sanitized, "reason": "webhook_not_configured"}))

    if settings.notification_email_enabled:
        logs.append(send_email_notification(db, sanitized))
    return logs


def send_webhook_notification(db: Session, event: dict[str, Any]) -> models.NotificationLog:
    """Send one generic webhook notification."""
    target = "configured:true"
    try:
        request = urllib.request.Request(
            settings.notification_webhook_url or "",
            data=json.dumps(event).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "HexSOC-AI-Notifier/1.0"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=DEFAULT_TIMEOUT_SECONDS) as response:
            outcome = "success" if 200 <= int(response.status) < 300 else "failure"
            return _add_log(db, event_type=event["event_type"], channel="webhook", target=target, outcome=outcome, metadata={**event, "status_code": response.status})
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        logger.warning("Notification webhook failed for %s: %s", event.get("event_type"), exc.__class__.__name__)
        return _add_log(db, event_type=event["event_type"], channel="webhook", target=target, outcome="failure", error_message=exc.__class__.__name__, metadata=event)


def send_email_notification(db: Session, event: dict[str, Any]) -> models.NotificationLog:
    """Placeholder email notification until SMTP/provider settings exist."""
    target = "configured:true" if settings.notification_email_to else "configured:false"
    outcome = "skipped"
    reason = "email_provider_not_configured"
    return _add_log(db, event_type=event["event_type"], channel="email", target=target, outcome=outcome, metadata={**event, "reason": reason})


def notification_status() -> dict[str, Any]:
    """Return provider status without exposing secrets."""
    return {
        "notifications_enabled": settings.notifications_enabled,
        "webhook_configured": bool(settings.notification_webhook_url),
        "email_enabled": settings.notification_email_enabled,
        "email_configured": bool(settings.notification_email_from and settings.notification_email_to),
        "rate_limit_seconds": settings.notification_rate_limit_seconds,
    }


def serialize_notification_log(log: models.NotificationLog) -> dict[str, Any]:
    """Convert a notification log to API-safe JSON."""
    return {
        "id": log.id,
        "event_type": log.event_type,
        "channel": log.channel,
        "target": log.target,
        "outcome": log.outcome,
        "error_message": log.error_message,
        "metadata": log.notification_metadata or {},
        "created_at": log.created_at.isoformat() if log.created_at else None,
    }


def _notification_payload(event_type: str, title: str, message: str, severity: str, metadata: dict[str, Any]) -> dict[str, Any]:
    return sanitize_metadata(
        {
            "event_type": event_type[:120],
            "title": title[:180],
            "message": message[:800],
            "severity": severity[:40],
            "metadata": metadata,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
    )


def _is_rate_limited(db: Session, event_type: str) -> bool:
    if settings.notification_rate_limit_seconds <= 0:
        return False
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.notification_rate_limit_seconds)
    recent = (
        db.query(models.NotificationLog)
        .filter(
            models.NotificationLog.event_type == event_type,
            models.NotificationLog.outcome == "success",
            models.NotificationLog.created_at >= cutoff,
        )
        .first()
    )
    return recent is not None


def _add_log(
    db: Session,
    *,
    event_type: str,
    channel: str,
    target: str | None,
    outcome: str,
    metadata: dict[str, Any],
    error_message: str | None = None,
) -> models.NotificationLog:
    log = models.NotificationLog(
        event_type=event_type[:120],
        channel=channel[:80],
        target=target[:255] if target else None,
        outcome=outcome[:40],
        error_message=error_message[:500] if error_message else None,
        notification_metadata=sanitize_metadata(metadata),
    )
    db.add(log)
    return log


def notification_summary(db: Session) -> dict[str, Any]:
    """Return compact notification status and outcome summary."""
    total = db.query(func.count(models.NotificationLog.id)).scalar() or 0
    failures = db.query(func.count(models.NotificationLog.id)).filter(models.NotificationLog.outcome == "failure").scalar() or 0
    sent = db.query(func.count(models.NotificationLog.id)).filter(models.NotificationLog.outcome == "success").scalar() or 0
    skipped = db.query(func.count(models.NotificationLog.id)).filter(models.NotificationLog.outcome == "skipped").scalar() or 0
    recent = db.query(models.NotificationLog).order_by(models.NotificationLog.id.desc()).limit(10).all()
    return {
        **notification_status(),
        "total": total,
        "sent": sent,
        "failures": failures,
        "skipped": skipped,
        "recent": [serialize_notification_log(log) for log in recent],
    }
