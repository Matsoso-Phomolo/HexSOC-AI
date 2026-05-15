"""MISP REST adapter for explicit IOC attribute searches."""

from __future__ import annotations

import json
from urllib.request import Request

from app.services.ioc_normalizer import NormalizedIOC
from app.services.threat_intel_adapters.provider_base import ThreatIntelProviderAdapter, provider_result, safe_json_request


class MISPAdapter(ThreatIntelProviderAdapter):
    name = "misp"
    supported_ioc_types = {"ip", "domain", "url", "hash", "email", "cve"}

    def __init__(self, api_key: str | None, *, base_url: str | None, timeout_seconds: int = 8) -> None:
        super().__init__(api_key, timeout_seconds=timeout_seconds, base_url=(base_url or "").rstrip("/"))

    @property
    def configured(self) -> bool:
        return bool(self.api_key and self.base_url)

    def _lookup(self, normalized: NormalizedIOC) -> dict:
        body = json.dumps({"value": normalized.normalized_value, "returnFormat": "json", "limit": 10}).encode("utf-8")
        request = Request(
            f"{self.base_url}/attributes/restSearch",
            data=body,
            method="POST",
            headers={
                "Authorization": self.api_key or "",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        payload, error = safe_json_request(request, self.timeout_seconds)
        if error:
            return provider_result(self.name, normalized, error=error)

        response = payload.get("response", {}) if payload else {}
        attributes = response.get("Attribute") or payload.get("Attribute") or []
        if isinstance(attributes, dict):
            attributes = [attributes]
        count = len(attributes)
        score = min(100, count * 20)
        tags = {"misp"}
        for attribute in attributes[:5]:
            for tag in attribute.get("Tag", []) or []:
                if tag.get("name"):
                    tags.add(tag["name"])
        return provider_result(
            self.name,
            normalized,
            matched=count > 0,
            severity=_severity(score),
            confidence_score=min(100, 50 + count * 10) if count else 20,
            risk_score=score,
            tags=sorted(tags)[:8],
            source_reputation=score,
            raw_context={"attribute_count": count},
        )


def _severity(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 20:
        return "medium"
    return "info"
