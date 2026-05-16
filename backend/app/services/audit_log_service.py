"""Enterprise audit logging helpers for sensitive SOC actions."""

from __future__ import annotations

from datetime import datetime, date
from typing import Any

from fastapi import Request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db import models


SENSITIVE_KEYS = {
    "api_key",
    "api_key_hash",
    "authorization",
    "collector_api_key",
    "hashed_password",
    "jwt",
    "password",
    "raw_api_key",
    "secret",
    "token",
    "x-hexsoc-api-key",
}
MAX_METADATA_DEPTH = 4
MAX_METADATA_ITEMS = 50
MAX_STRING_LENGTH = 500


def write_audit_log(
    db: Session,
    *,
    action: str,
    category: str,
    outcome: str = "success",
    actor: models.User | None = None,
    actor_user_id: int | None = None,
    actor_username: str | None = None,
    actor_role: str | None = None,
    request: Request | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    target_label: str | None = None,
    request_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> models.AuditLog | None:
    """Write one sanitized audit record without leaking secrets."""
    if actor:
        actor_user_id = actor_user_id if actor_user_id is not None else getattr(actor, "id", None)
        actor_username = actor_username or getattr(actor, "username", None)
        actor_role = actor_role or getattr(actor, "role", None)

    audit = models.AuditLog(
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_role=actor_role,
        action=_bounded_string(action, 120) or "unknown_action",
        category=_bounded_string(category, 80) or "system",
        target_type=_bounded_string(target_type, 80),
        target_id=_bounded_string(str(target_id), 120) if target_id is not None else None,
        target_label=_bounded_string(target_label, 255),
        outcome=_bounded_string(outcome, 40) or "success",
        ip_address=_client_ip(request),
        user_agent=_bounded_string(request.headers.get("user-agent"), 500) if request else None,
        request_id=_bounded_string(request_id or (request.headers.get("x-request-id") if request else None), 120),
        audit_metadata=sanitize_metadata(metadata or {}),
    )
    try:
        db.add(audit)
        return audit
    except SQLAlchemyError:
        db.rollback()
        return None


def log_success(db: Session, **kwargs: Any) -> models.AuditLog | None:
    """Write a successful audit event."""
    return write_audit_log(db, outcome="success", **kwargs)


def log_failure(db: Session, **kwargs: Any) -> models.AuditLog | None:
    """Write a failed audit event."""
    return write_audit_log(db, outcome="failure", **kwargs)


def log_denied(db: Session, **kwargs: Any) -> models.AuditLog | None:
    """Write a denied audit event."""
    return write_audit_log(db, outcome="denied", **kwargs)


def sanitize_metadata(value: Any, *, depth: int = 0) -> Any:
    """Return bounded JSON-safe metadata with secrets redacted."""
    if depth > MAX_METADATA_DEPTH:
        return "[truncated]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, str):
        return _bounded_string(value, MAX_STRING_LENGTH)
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_METADATA_ITEMS:
                sanitized["__truncated__"] = True
                break
            key_text = str(key)
            if _is_sensitive_key(key_text):
                sanitized[key_text] = "[redacted]"
            else:
                sanitized[key_text] = sanitize_metadata(item, depth=depth + 1)
        return sanitized
    if isinstance(value, (list, tuple, set)):
        items = list(value)[:MAX_METADATA_ITEMS]
        sanitized_items = [sanitize_metadata(item, depth=depth + 1) for item in items]
        if len(value) > MAX_METADATA_ITEMS:
            sanitized_items.append({"__truncated__": True})
        return sanitized_items
    return _bounded_string(str(value), MAX_STRING_LENGTH)


def serialize_audit_log(audit: models.AuditLog) -> dict[str, Any]:
    """Convert an audit record to API-safe JSON."""
    return {
        "id": audit.id,
        "actor_user_id": audit.actor_user_id,
        "actor_username": audit.actor_username,
        "actor_role": audit.actor_role,
        "action": audit.action,
        "category": audit.category,
        "target_type": audit.target_type,
        "target_id": audit.target_id,
        "target_label": audit.target_label,
        "outcome": audit.outcome,
        "ip_address": audit.ip_address,
        "user_agent": audit.user_agent,
        "request_id": audit.request_id,
        "metadata": audit.audit_metadata or {},
        "created_at": audit.created_at.isoformat() if audit.created_at else None,
    }


def _is_sensitive_key(key: str) -> bool:
    key_lower = key.lower().replace("-", "_")
    return any(sensitive in key_lower for sensitive in SENSITIVE_KEYS)


def _bounded_string(value: str | None, max_length: int) -> str | None:
    if value is None:
        return None
    text = str(value)
    if len(text) <= max_length:
        return text
    return f"{text[: max_length - 15]}...[truncated]"


def _client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return request.client.host if request.client else None
