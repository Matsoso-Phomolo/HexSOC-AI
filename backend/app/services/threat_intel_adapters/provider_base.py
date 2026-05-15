"""Base primitives for explicit threat intelligence provider lookups."""

from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app.services.ioc_normalizer import NormalizedIOC


class ThreatIntelProviderAdapter:
    """Small provider adapter interface for controlled external lookups."""

    name = "provider"
    supported_ioc_types: set[str] = set()

    def __init__(self, api_key: str | None = None, *, timeout_seconds: int = 8, base_url: str | None = None) -> None:
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.base_url = base_url

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def supports(self, normalized: NormalizedIOC) -> bool:
        return normalized.ioc_type in self.supported_ioc_types

    def status(self, *, cache_ttl: int) -> dict[str, Any]:
        return {
            "provider": self.name,
            "enabled": self.configured,
            "configured": self.configured,
            "supported_ioc_types": sorted(self.supported_ioc_types),
            "cache_ttl": cache_ttl,
            "timeout": self.timeout_seconds,
        }

    def lookup(self, normalized: NormalizedIOC) -> dict[str, Any]:
        if not self.configured:
            return provider_result(self.name, normalized, error="Provider API key is not configured")
        if not self.supports(normalized):
            return provider_result(self.name, normalized, error=f"IOC type {normalized.ioc_type} is not supported")
        return self._lookup(normalized)

    def _lookup(self, normalized: NormalizedIOC) -> dict[str, Any]:
        raise NotImplementedError


def provider_result(
    provider: str,
    normalized: NormalizedIOC,
    *,
    matched: bool = False,
    severity: str = "info",
    confidence_score: int = 0,
    risk_score: int = 0,
    tags: list[str] | None = None,
    source_reputation: int = 0,
    raw_context: dict[str, Any] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    """Build provider-neutral enrichment response."""
    return {
        "provider": provider,
        "ioc_type": normalized.ioc_type,
        "value": normalized.value,
        "normalized_value": normalized.normalized_value,
        "matched": matched,
        "severity": severity,
        "confidence_score": max(0, min(confidence_score, 100)),
        "risk_score": max(0, min(risk_score, 100)),
        "tags": tags or [],
        "source_reputation": max(0, min(source_reputation, 100)),
        "raw_context": raw_context or {},
        "error": error,
    }


def safe_json_request(request: Request, timeout_seconds: int) -> tuple[dict[str, Any] | None, str | None]:
    """Perform a bounded JSON request and return sanitized errors."""
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            body = response.read(1_000_000)
            return json.loads(body.decode("utf-8")), None
    except HTTPError as exc:
        return None, f"Provider returned HTTP {exc.code}"
    except URLError:
        return None, "Provider network error"
    except TimeoutError:
        return None, "Provider request timed out"
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, "Provider returned invalid JSON"
