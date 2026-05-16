"""Authentication helpers for HexSOC AI."""

import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Callable

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db import models
from app.db.database import get_db_session


ALLOWED_ROLES = {"admin", "analyst", "viewer"}
SUPER_ADMIN_EMAIL = "phomolomatsoso@gmail.com"
SUPER_ADMIN_NAME = "PHOMOLO MATSOSO"
PENDING_ADMIN_APPROVAL_REASON = f"Pending super admin approval by {SUPER_ADMIN_NAME} <{SUPER_ADMIN_EMAIL}>"


def hash_password(password: str) -> str:
    """Hash a password using PBKDF2-SHA256 with a per-password salt."""
    salt = os.urandom(16)
    iterations = 260_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, hashed_password: str) -> bool:
    """Verify a PBKDF2-SHA256 password hash."""
    try:
        algorithm, iterations, salt, expected = hashed_password.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            _b64decode(salt),
            int(iterations),
        )
        return hmac.compare_digest(_b64(digest), expected)
    except (ValueError, TypeError):
        return False


def create_access_token(user: models.User, expires_minutes: int = 480) -> str:
    """Create a signed HMAC JWT for an authenticated user."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
    }
    header = {"alg": settings.jwt_algorithm, "typ": "JWT"}
    signing_input = f"{_json_b64(header)}.{_json_b64(payload)}"
    signature = _sign(signing_input)
    return f"{signing_input}.{signature}"


def decode_access_token(token: str) -> dict:
    """Decode and validate a signed HMAC JWT."""
    try:
        header_b64, payload_b64, signature = token.split(".", 2)
        signing_input = f"{header_b64}.{payload_b64}"
        if not hmac.compare_digest(_sign(signing_input), signature):
            raise ValueError("Invalid signature")
        payload = json.loads(_b64decode(payload_b64))
        if int(payload.get("exp", 0)) < int(datetime.now(timezone.utc).timestamp()):
            raise ValueError("Expired token")
        return payload
    except (ValueError, json.JSONDecodeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_current_user(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db_session),
) -> models.User:
    """FastAPI dependency returning the authenticated active user."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_access_token(authorization.split(" ", 1)[1])
    user = db.get(models.User, int(payload["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive or missing user")
    return user


def require_role(*roles: str) -> Callable:
    """Return dependency enforcing one of the provided roles, with admin override."""
    allowed = set(roles)

    def dependency(user: models.User = Depends(get_current_user)) -> models.User:
        if user.role == "admin" or user.role in allowed:
            return user
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")

    return dependency


def get_user_by_login(db: Session, username_or_email: str) -> models.User | None:
    return (
        db.query(models.User)
        .filter(or_(models.User.username == username_or_email, models.User.email == username_or_email))
        .first()
    )


def normalize_role(role: str) -> str:
    normalized = (role or "analyst").lower()
    return normalized if normalized in ALLOWED_ROLES else "analyst"


def is_super_admin(user: models.User | None) -> bool:
    """Return whether a user is the designated HexSOC AI super admin."""
    return bool(user and user.role == "admin" and (user.email or "").strip().lower() == SUPER_ADMIN_EMAIL)


def is_pending_admin_approval(user: models.User | None) -> bool:
    """Return whether an admin account is waiting for super-admin approval."""
    return bool(
        user
        and user.role == "admin"
        and not user.is_active
        and (user.disabled_reason or "") == PENDING_ADMIN_APPROVAL_REASON
    )


def _sign(value: str) -> str:
    digest = hmac.new(settings.jwt_secret_key.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).digest()
    return _b64(digest)


def _json_b64(value: dict) -> str:
    return _b64(json.dumps(value, separators=(",", ":")).encode("utf-8"))


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
