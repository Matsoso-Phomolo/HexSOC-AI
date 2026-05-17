"""Session security and access-governance helpers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from fastapi import Request
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db import models


LOCKED_OUT = "locked"
BLOCKED = "blocked"
FAILURE = "failure"
SUCCESS = "success"


def new_session_id() -> str:
    """Return a random session identifier safe to embed as JWT jti."""
    return uuid4().hex


def create_user_session(
    db: Session,
    user: models.User,
    *,
    request: Request | None = None,
    token_jti: str | None = None,
    expires_at: datetime | None = None,
) -> models.UserSession:
    """Create a server-side session record for a just-issued token."""
    now = datetime.now(timezone.utc)
    session = models.UserSession(
        user_id=user.id,
        token_jti=token_jti or new_session_id(),
        created_at=now,
        last_seen_at=now,
        expires_at=expires_at or now + timedelta(minutes=settings.access_token_expire_minutes),
        ip_address=client_ip(request),
        user_agent=bounded_user_agent(request),
        is_active=True,
    )
    db.add(session)
    return session


def validate_session(db: Session, token_jti: str | None) -> models.UserSession | None:
    """Return an active session or None for legacy tokens without jti."""
    if not token_jti:
        return None
    session = db.query(models.UserSession).filter(models.UserSession.token_jti == token_jti).first()
    if session is None:
        raise SessionRejected("Session was not found")
    now = datetime.now(timezone.utc)
    if session.revoked_at or not session.is_active:
        raise SessionRejected("Session was revoked")
    if session.expires_at and _as_aware(session.expires_at) < now:
        session.is_active = False
        session.revoked_at = now
        session.revoked_reason = "expired"
        db.add(session)
        db.commit()
        raise SessionRejected("Session expired")
    if is_idle_expired(session, now=now):
        session.is_active = False
        session.revoked_at = now
        session.revoked_reason = "idle_timeout"
        db.add(session)
        db.commit()
        raise SessionRejected("Session idle timeout")
    session.last_seen_at = now
    db.add(session)
    db.commit()
    return session


def is_idle_expired(session: models.UserSession, *, now: datetime | None = None) -> bool:
    """Return whether session last activity exceeds configured idle timeout."""
    if settings.session_idle_timeout_minutes <= 0:
        return False
    last_seen = _as_aware(session.last_seen_at or session.created_at)
    if not last_seen:
        return False
    return (now or datetime.now(timezone.utc)) - last_seen > timedelta(minutes=settings.session_idle_timeout_minutes)


def revoke_session(db: Session, session: models.UserSession, *, reason: str = "revoked") -> models.UserSession:
    """Mark one session inactive."""
    if not session.revoked_at:
        session.revoked_at = datetime.now(timezone.utc)
    session.revoked_reason = reason
    session.is_active = False
    db.add(session)
    return session


def revoke_user_sessions(
    db: Session,
    user_id: int,
    *,
    reason: str = "logout_all",
    exclude_jti: str | None = None,
) -> int:
    """Revoke active sessions for one user and return count."""
    query = db.query(models.UserSession).filter(
        models.UserSession.user_id == user_id,
        models.UserSession.is_active.is_(True),
        models.UserSession.revoked_at.is_(None),
    )
    if exclude_jti:
        query = query.filter(models.UserSession.token_jti != exclude_jti)
    sessions = query.limit(500).all()
    for session in sessions:
        revoke_session(db, session, reason=reason)
    return len(sessions)


def record_login_attempt(
    db: Session,
    *,
    username: str,
    request: Request | None,
    outcome: str,
    reason: str,
) -> models.LoginAttempt:
    """Store one bounded login attempt record."""
    attempt = models.LoginAttempt(
        email_or_username=(username or "unknown").strip().lower()[:120],
        ip_address=client_ip(request),
        user_agent=bounded_user_agent(request),
        outcome=outcome,
        reason=reason[:255] if reason else None,
    )
    db.add(attempt)
    return attempt


def is_identity_locked(db: Session, username: str, *, request: Request | None = None) -> bool:
    """Return whether an identity/IP has too many recent failures."""
    if settings.max_failed_login_attempts <= 0:
        return False
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=settings.account_lockout_minutes)
    normalized = (username or "").strip().lower()
    filters = [models.LoginAttempt.email_or_username == normalized]
    ip_address = client_ip(request)
    if ip_address:
        filters.append(models.LoginAttempt.ip_address == ip_address)
    failures = (
        db.query(models.LoginAttempt)
        .filter(
            models.LoginAttempt.created_at >= cutoff,
            models.LoginAttempt.outcome.in_((FAILURE, LOCKED_OUT, BLOCKED)),
            or_(*filters),
        )
        .order_by(models.LoginAttempt.id.desc())
        .limit(settings.max_failed_login_attempts)
        .all()
    )
    return len(failures) >= settings.max_failed_login_attempts


def session_to_dict(session: models.UserSession) -> dict[str, Any]:
    """Serialize a session without exposing token material."""
    return {
        "id": session.id,
        "user_id": session.user_id,
        "session_id": session.token_jti,
        "created_at": session.created_at.isoformat() if session.created_at else None,
        "last_seen_at": session.last_seen_at.isoformat() if session.last_seen_at else None,
        "expires_at": session.expires_at.isoformat() if session.expires_at else None,
        "revoked_at": session.revoked_at.isoformat() if session.revoked_at else None,
        "revoked_reason": session.revoked_reason,
        "ip_address": session.ip_address,
        "user_agent": session.user_agent,
        "is_active": bool(session.is_active and not session.revoked_at),
        "suspicious": is_suspicious_session(session),
    }


def login_attempt_to_dict(attempt: models.LoginAttempt) -> dict[str, Any]:
    """Serialize a login attempt for governance views."""
    return {
        "id": attempt.id,
        "email_or_username": attempt.email_or_username,
        "ip_address": attempt.ip_address,
        "user_agent": attempt.user_agent,
        "outcome": attempt.outcome,
        "reason": attempt.reason,
        "created_at": attempt.created_at.isoformat() if attempt.created_at else None,
    }


def is_suspicious_session(session: models.UserSession) -> bool:
    """Lightweight suspicious-session heuristic."""
    return bool(session.revoked_reason in {"expired_token_reuse", "idle_timeout"} or not session.ip_address)


def client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return request.client.host[:64] if request.client and request.client.host else None


def bounded_user_agent(request: Request | None) -> str | None:
    if request is None:
        return None
    user_agent = request.headers.get("user-agent")
    return user_agent[:500] if user_agent else None


def _as_aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class SessionRejected(Exception):
    """Raised when a server-side session fails governance checks."""
