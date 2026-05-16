"""Audit and compliance log API routes."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.security.permissions import Permission, require_permission
from app.services.audit_log_service import serialize_audit_log

router = APIRouter()


@router.get("/logs", summary="List audit logs")
def list_audit_logs(
    category: str | None = Query(default=None, max_length=80),
    action: str | None = Query(default=None, max_length=120),
    actor: str | None = Query(default=None, max_length=120),
    target_type: str | None = Query(default=None, max_length=80),
    outcome: str | None = Query(default=None, max_length=40),
    date_from: datetime | None = Query(default=None),
    date_to: datetime | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_permission(Permission.AUDIT_READ)),
) -> dict[str, Any]:
    """Return bounded audit logs for admin and super-admin review."""
    query = db.query(models.AuditLog)
    if category:
        query = query.filter(models.AuditLog.category == category.strip())
    if action:
        query = query.filter(models.AuditLog.action == action.strip())
    if actor:
        pattern = f"%{actor.strip()}%"
        query = query.filter(models.AuditLog.actor_username.ilike(pattern))
    if target_type:
        query = query.filter(models.AuditLog.target_type == target_type.strip())
    if outcome:
        query = query.filter(models.AuditLog.outcome == outcome.strip())
    if date_from:
        query = query.filter(models.AuditLog.created_at >= date_from)
    if date_to:
        query = query.filter(models.AuditLog.created_at <= date_to)

    logs = query.order_by(models.AuditLog.id.desc()).limit(limit).all()
    return {"total": len(logs), "limit": limit, "logs": [serialize_audit_log(log) for log in logs]}


@router.get("/logs/{audit_id}", summary="Get audit log")
def get_audit_log(
    audit_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_permission(Permission.AUDIT_READ)),
) -> dict[str, Any]:
    """Return one audit record."""
    audit = db.get(models.AuditLog, audit_id)
    if audit is None:
        raise HTTPException(status_code=404, detail="Audit log not found")
    return serialize_audit_log(audit)


@router.get("/summary", summary="Audit compliance summary")
def audit_summary(
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_permission(Permission.AUDIT_READ)),
) -> dict[str, Any]:
    """Return compact audit statistics and recent high-risk outcomes."""
    total = db.query(func.count(models.AuditLog.id)).scalar() or 0
    failures = db.query(func.count(models.AuditLog.id)).filter(models.AuditLog.outcome == "failure").scalar() or 0
    denied = db.query(func.count(models.AuditLog.id)).filter(models.AuditLog.outcome == "denied").scalar() or 0
    by_category = (
        db.query(models.AuditLog.category, func.count(models.AuditLog.id).label("count"))
        .group_by(models.AuditLog.category)
        .order_by(func.count(models.AuditLog.id).desc())
        .limit(10)
        .all()
    )
    by_outcome = (
        db.query(models.AuditLog.outcome, func.count(models.AuditLog.id).label("count"))
        .group_by(models.AuditLog.outcome)
        .order_by(func.count(models.AuditLog.id).desc())
        .all()
    )
    recent_high_risk = (
        db.query(models.AuditLog)
        .filter(models.AuditLog.outcome.in_(("failure", "denied")))
        .order_by(models.AuditLog.id.desc())
        .limit(min(limit, 25))
        .all()
    )
    return {
        "total": total,
        "failures": failures,
        "denied": denied,
        "by_category": [{"category": category or "unknown", "count": count} for category, count in by_category],
        "by_outcome": [{"outcome": outcome or "unknown", "count": count} for outcome, count in by_outcome],
        "recent_high_risk": [serialize_audit_log(log) for log in recent_high_risk],
    }
