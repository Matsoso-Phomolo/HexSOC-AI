"""VirusTotal API v3 adapter for explicit IOC lookups."""

from __future__ import annotations

import base64
from urllib.parse import quote
from urllib.request import Request

from app.services.ioc_normalizer import NormalizedIOC
from app.services.threat_intel_adapters.provider_base import ThreatIntelProviderAdapter, provider_result, safe_json_request


class VirusTotalAdapter(ThreatIntelProviderAdapter):
    name = "virustotal"
    supported_ioc_types = {"ip", "domain", "url", "hash"}

    def __init__(self, api_key: str | None, *, timeout_seconds: int = 8) -> None:
        super().__init__(api_key, timeout_seconds=timeout_seconds, base_url="https://www.virustotal.com/api/v3")

    def _lookup(self, normalized: NormalizedIOC) -> dict:
        endpoint = self._endpoint(normalized)
        request = Request(endpoint, headers={"x-apikey": self.api_key or "", "Accept": "application/json"})
        payload, error = safe_json_request(request, self.timeout_seconds)
        if error:
            return provider_result(self.name, normalized, error=error)

        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) if payload else {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        total = sum(int(value or 0) for value in stats.values()) or 1
        reputation = min(100, int(((malicious + suspicious) / total) * 100))
        return provider_result(
            self.name,
            normalized,
            matched=malicious > 0 or suspicious > 0,
            severity=_severity(reputation),
            confidence_score=min(100, reputation + 20 if reputation else 30),
            risk_score=reputation,
            tags=["virustotal", "reputation"],
            source_reputation=reputation,
            raw_context={"last_analysis_stats": stats},
        )

    def _endpoint(self, normalized: NormalizedIOC) -> str:
        if normalized.ioc_type == "ip":
            return f"{self.base_url}/ip_addresses/{quote(normalized.normalized_value)}"
        if normalized.ioc_type == "domain":
            return f"{self.base_url}/domains/{quote(normalized.normalized_value)}"
        if normalized.ioc_type == "url":
            url_id = base64.urlsafe_b64encode(normalized.normalized_value.encode("utf-8")).decode("ascii").rstrip("=")
            return f"{self.base_url}/urls/{url_id}"
        return f"{self.base_url}/files/{quote(normalized.normalized_value)}"


def _severity(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 20:
        return "medium"
    return "info"
