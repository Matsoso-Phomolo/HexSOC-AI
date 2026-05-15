"""AlienVault OTX DirectConnect adapter for explicit IOC lookups."""

from __future__ import annotations

from urllib.parse import quote
from urllib.request import Request

from app.services.ioc_normalizer import NormalizedIOC
from app.services.threat_intel_adapters.provider_base import ThreatIntelProviderAdapter, provider_result, safe_json_request


class OTXAdapter(ThreatIntelProviderAdapter):
    name = "otx"
    supported_ioc_types = {"ip", "domain", "url", "hash"}

    def __init__(self, api_key: str | None, *, timeout_seconds: int = 8) -> None:
        super().__init__(api_key, timeout_seconds=timeout_seconds, base_url="https://otx.alienvault.com/api/v1")

    def _lookup(self, normalized: NormalizedIOC) -> dict:
        otx_type = {"ip": "IPv4", "domain": "domain", "url": "url", "hash": "file"}.get(normalized.ioc_type, "domain")
        request = Request(
            f"{self.base_url}/indicators/{otx_type}/{quote(normalized.normalized_value, safe='')}/general",
            headers={"X-OTX-API-KEY": self.api_key or "", "Accept": "application/json"},
        )
        payload, error = safe_json_request(request, self.timeout_seconds)
        if error:
            return provider_result(self.name, normalized, error=error)

        pulse_info = payload.get("pulse_info", {}) if payload else {}
        count = int(pulse_info.get("count") or 0)
        tags = ["otx"] + [str(tag) for tag in (pulse_info.get("related", {}).get("alienvault", {}).get("tags") or [])[:5]]
        score = min(100, count * 15)
        return provider_result(
            self.name,
            normalized,
            matched=count > 0,
            severity=_severity(score),
            confidence_score=min(100, 40 + count * 10) if count else 20,
            risk_score=score,
            tags=tags,
            source_reputation=score,
            raw_context={"pulse_count": count, "sections": list(payload.keys())[:10] if payload else []},
        )


def _severity(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 20:
        return "medium"
    return "info"
