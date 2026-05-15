"""AbuseIPDB API v2 adapter for explicit IP reputation lookups."""

from __future__ import annotations

from urllib.parse import urlencode
from urllib.request import Request

from app.services.ioc_normalizer import NormalizedIOC
from app.services.threat_intel_adapters.provider_base import ThreatIntelProviderAdapter, provider_result, safe_json_request


class AbuseIPDBAdapter(ThreatIntelProviderAdapter):
    name = "abuseipdb"
    supported_ioc_types = {"ip"}

    def __init__(self, api_key: str | None, *, timeout_seconds: int = 8) -> None:
        super().__init__(api_key, timeout_seconds=timeout_seconds, base_url="https://api.abuseipdb.com/api/v2/check")

    def _lookup(self, normalized: NormalizedIOC) -> dict:
        params = urlencode({"ipAddress": normalized.normalized_value, "maxAgeInDays": "90", "verbose": "true"})
        request = Request(
            f"{self.base_url}?{params}",
            headers={"Key": self.api_key or "", "Accept": "application/json"},
        )
        payload, error = safe_json_request(request, self.timeout_seconds)
        if error:
            return provider_result(self.name, normalized, error=error)

        data = payload.get("data", {}) if payload else {}
        score = int(data.get("abuseConfidenceScore") or 0)
        return provider_result(
            self.name,
            normalized,
            matched=score > 0,
            severity=_severity(score),
            confidence_score=score,
            risk_score=score,
            tags=["abuseipdb", "ip_reputation"],
            source_reputation=score,
            raw_context={
                "total_reports": data.get("totalReports"),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "usage_type": data.get("usageType"),
                "last_reported_at": data.get("lastReportedAt"),
            },
        )


def _severity(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 30:
        return "medium"
    return "info"
