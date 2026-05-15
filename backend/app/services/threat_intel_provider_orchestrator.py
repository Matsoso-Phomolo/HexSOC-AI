"""Provider orchestrator for explicit threat intelligence enrichment requests."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.schemas.threat_ioc import ThreatIOCCreate
from app.services.ioc_normalizer import NormalizedIOC, normalize_ioc_value
from app.services.threat_intel_adapters.abuseipdb import AbuseIPDBAdapter
from app.services.threat_intel_adapters.misp import MISPAdapter
from app.services.threat_intel_adapters.otx import OTXAdapter
from app.services.threat_intel_adapters.provider_base import ThreatIntelProviderAdapter, provider_result
from app.services.threat_intel_adapters.virustotal import VirusTotalAdapter
from app.services.threat_intel_cache import cache_key, get_cached_provider_result, set_cached_provider_result
from app.services.threat_intel_feed_service import ingest_iocs


PROVIDER_ORDER = ("virustotal", "abuseipdb", "otx", "misp")
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def provider_status() -> list[dict[str, Any]]:
    """Return provider readiness without exposing secrets."""
    adapters = _adapters()
    return [
        adapters[name].status(cache_ttl=settings.threat_intel_provider_cache_ttl_seconds)
        for name in PROVIDER_ORDER
    ]


def enrich_indicators(
    db: Session,
    indicators: list[str],
    *,
    providers: list[str] | None = None,
    persist: bool = False,
    actor_username: str | None = None,
    actor_role: str | None = None,
) -> dict[str, Any]:
    """Run explicit, bounded provider enrichment for supplied indicators."""
    max_lookups = settings.threat_intel_provider_max_lookups_per_request
    bounded_indicators = indicators[:max_lookups]
    selected_provider_names = _selected_providers(providers)
    adapters = _adapters()

    results: list[dict[str, Any]] = []
    provider_errors: list[dict[str, str]] = []
    skipped = 0
    persisted_records: list[ThreatIOCCreate] = []

    for raw_indicator in bounded_indicators:
        normalized = normalize_ioc_value(raw_indicator)
        if not normalized.is_valid:
            skipped += 1
            results.append({"indicator": raw_indicator, "error": normalized.reason, "provider_results": [], "fused_result": None})
            continue

        provider_results = []
        for provider_name in selected_provider_names:
            adapter = adapters[provider_name]
            if not adapter.supports(normalized):
                continue
            result = _cached_or_lookup(adapter, normalized)
            if result.get("error"):
                provider_errors.append({"provider": provider_name, "indicator": normalized.normalized_value, "error": result["error"]})
            provider_results.append(result)

        fused = _fuse_results(normalized, provider_results)
        if persist and fused:
            persisted_records.append(_ioc_from_fused_result(fused))
        results.append({"indicator": raw_indicator, "provider_results": provider_results, "fused_result": fused})

    persist_summary = None
    if persist and persisted_records:
        persist_summary = ingest_iocs(db, persisted_records, actor_username=actor_username, actor_role=actor_role)

    enriched = sum(1 for result in results if result.get("fused_result", {}).get("matched"))
    return {
        "total_received": len(indicators),
        "enriched": enriched,
        "skipped": skipped + max(0, len(indicators) - len(bounded_indicators)),
        "provider_errors": provider_errors[:50],
        "results": results,
        "persisted": persist_summary,
        "limits": {
            "max_lookups_per_request": max_lookups,
            "processed": len(bounded_indicators),
        },
    }


def _adapters() -> dict[str, ThreatIntelProviderAdapter]:
    timeout = settings.threat_intel_provider_timeout_seconds
    return {
        "virustotal": VirusTotalAdapter(settings.virustotal_api_key, timeout_seconds=timeout),
        "abuseipdb": AbuseIPDBAdapter(settings.abuseipdb_api_key, timeout_seconds=timeout),
        "otx": OTXAdapter(settings.otx_api_key, timeout_seconds=timeout),
        "misp": MISPAdapter(settings.misp_api_key, base_url=settings.misp_url, timeout_seconds=timeout),
    }


def _selected_providers(providers: list[str] | None) -> list[str]:
    if not providers:
        return list(PROVIDER_ORDER)
    requested = {provider.lower().strip() for provider in providers}
    return [provider for provider in PROVIDER_ORDER if provider in requested]


def _cached_or_lookup(adapter: ThreatIntelProviderAdapter, normalized: NormalizedIOC) -> dict[str, Any]:
    if not adapter.configured:
        return provider_result(adapter.name, normalized, error="Provider is not configured")
    key = cache_key(adapter.name, normalized.ioc_type, normalized.normalized_value)
    cached = get_cached_provider_result(key, settings.threat_intel_provider_cache_ttl_seconds)
    if cached:
        return {**cached, "cached": True}
    result = adapter.lookup(normalized)
    set_cached_provider_result(key, result)
    return result


def _fuse_results(normalized: NormalizedIOC, provider_results: list[dict[str, Any]]) -> dict[str, Any]:
    successful = [result for result in provider_results if not result.get("error")]
    matched = [result for result in successful if result.get("matched")]
    if not successful:
        return {
            "provider": "fused",
            "ioc_type": normalized.ioc_type,
            "value": normalized.value,
            "normalized_value": normalized.normalized_value,
            "matched": False,
            "severity": "info",
            "confidence_score": 0,
            "risk_score": 0,
            "tags": [],
            "source_reputation": 0,
            "raw_context": {"providers_checked": [result["provider"] for result in provider_results]},
            "error": None,
        }

    risk_score = max((result.get("risk_score") or 0 for result in successful), default=0)
    confidence = max((result.get("confidence_score") or 0 for result in successful), default=0)
    severity = max((result.get("severity") or "info" for result in successful), key=lambda value: SEVERITY_RANK.get(value, 0))
    tags = sorted({tag for result in successful for tag in result.get("tags", [])})
    return {
        "provider": "fused",
        "ioc_type": normalized.ioc_type,
        "value": normalized.value,
        "normalized_value": normalized.normalized_value,
        "matched": bool(matched),
        "severity": severity,
        "confidence_score": confidence,
        "risk_score": risk_score,
        "tags": tags[:12],
        "source_reputation": risk_score,
        "raw_context": {
            "providers_checked": [result["provider"] for result in successful],
            "matched_providers": [result["provider"] for result in matched],
        },
        "error": None,
    }


def _ioc_from_fused_result(result: dict[str, Any]) -> ThreatIOCCreate:
    return ThreatIOCCreate(
        ioc_type=result["ioc_type"],
        value=result["value"],
        source="provider_fusion",
        confidence_score=result["confidence_score"],
        risk_score=result["risk_score"],
        severity=result["severity"],
        tags=result["tags"],
        classification="provider_enrichment",
        last_seen_at=datetime.now(timezone.utc),
        raw_context=result["raw_context"],
    )
