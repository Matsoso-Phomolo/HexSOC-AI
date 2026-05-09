"""Collector API key generation, hashing, and lookup."""

import hashlib
import hmac
import secrets
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db import models
from app.schemas.collector import CollectorCreate


def generate_api_key() -> tuple[str, str]:
    """Generate a raw collector API key and its display prefix."""
    prefix = secrets.token_urlsafe(6).replace("-", "").replace("_", "")[:8].lower()
    secret = secrets.token_urlsafe(32)
    return f"hexsoc_live_{prefix}_{secret}", prefix


def hash_api_key(api_key: str) -> str:
    """Hash an API key with an application secret for storage."""
    return hmac.new(settings.jwt_secret_key.encode("utf-8"), api_key.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_api_key(api_key: str, api_key_hash: str) -> bool:
    """Constant-time API key hash comparison."""
    return hmac.compare_digest(hash_api_key(api_key), api_key_hash)


def create_collector(db: Session, payload: CollectorCreate, created_by: str | None = None) -> tuple[models.Collector, str]:
    """Create a collector and return the one-time raw API key."""
    api_key, prefix = generate_api_key()
    collector = models.Collector(
        name=payload.name.strip(),
        description=payload.description,
        api_key_hash=hash_api_key(api_key),
        key_prefix=prefix,
        collector_type=(payload.collector_type or "custom_json").strip(),
        source_label=(payload.source_label or "").strip() or None,
        is_active=True,
        created_by=created_by,
    )
    db.add(collector)
    db.flush()
    return collector, api_key


def rotate_collector_key(db: Session, collector: models.Collector) -> tuple[models.Collector, str]:
    """Rotate a collector key and return the new raw key once."""
    api_key, prefix = generate_api_key()
    collector.api_key_hash = hash_api_key(api_key)
    collector.key_prefix = prefix
    collector.is_active = True
    collector.revoked_at = None
    db.add(collector)
    return collector, api_key


def revoke_collector(db: Session, collector: models.Collector) -> models.Collector:
    """Revoke a collector key."""
    collector.is_active = False
    collector.revoked_at = datetime.now(timezone.utc)
    db.add(collector)
    return collector


def get_collector_from_key(db: Session, api_key: str | None) -> models.Collector:
    """Resolve a collector from the X-HexSOC-API-Key header."""
    if not api_key or not api_key.startswith("hexsoc_live_"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Collector API key required")

    parts = api_key.split("_", 3)
    if len(parts) < 4:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid collector API key")
    prefix = parts[2]
    collectors = db.query(models.Collector).filter(models.Collector.key_prefix == prefix).all()
    collector = next((item for item in collectors if verify_api_key(api_key, item.api_key_hash)), None)
    if collector is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid collector API key")
    if not collector.is_active or collector.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Collector key is inactive or revoked")
    collector.last_seen_at = datetime.now(timezone.utc)
    db.add(collector)
    return collector
