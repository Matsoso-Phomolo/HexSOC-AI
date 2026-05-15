"""Small in-memory cache boundary for explicit threat provider lookups."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


_CACHE: dict[str, tuple[datetime, dict[str, Any]]] = {}


def cache_key(provider: str, ioc_type: str, normalized_value: str) -> str:
    """Build a provider lookup cache key without secrets."""
    return f"{provider}:{ioc_type}:{normalized_value}"


def get_cached_provider_result(key: str, ttl_seconds: int) -> dict[str, Any] | None:
    """Return a cached result when it is still within TTL."""
    cached = _CACHE.get(key)
    if not cached:
        return None
    created_at, result = cached
    if datetime.now(timezone.utc) - created_at > timedelta(seconds=ttl_seconds):
        _CACHE.pop(key, None)
        return None
    return result


def set_cached_provider_result(key: str, result: dict[str, Any]) -> None:
    """Store a sanitized provider result."""
    _CACHE[key] = (datetime.now(timezone.utc), result)
