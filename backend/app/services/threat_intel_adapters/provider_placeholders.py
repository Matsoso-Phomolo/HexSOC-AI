"""Provider-specific normalization placeholders for future feed integrations."""

from typing import Any

from app.schemas.threat_ioc import ThreatIOCCreate
from app.services.threat_intel_adapters.generic import normalize_generic_feed


def normalize_virustotal_feed(source: str, payload: dict[str, Any] | list[dict[str, Any]], default_ttl_days: int = 90) -> list[ThreatIOCCreate]:
    """Normalize VirusTotal-style already-fetched indicator payloads."""
    return normalize_generic_feed(source, _coerce_provider_records(payload, "virustotal"), default_ttl_days)


def normalize_abuseipdb_feed(source: str, payload: dict[str, Any] | list[dict[str, Any]], default_ttl_days: int = 90) -> list[ThreatIOCCreate]:
    """Normalize AbuseIPDB-style already-fetched indicator payloads."""
    records = _coerce_provider_records(payload, "abuseipdb")
    for record in records:
        record.setdefault("ioc_type", "ip")
        record.setdefault("value", record.get("ipAddress") or record.get("ip_address"))
        record.setdefault("risk_score", record.get("abuseConfidenceScore"))
        record.setdefault("confidence_score", record.get("abuseConfidenceScore"))
    return normalize_generic_feed(source, records, default_ttl_days)


def normalize_otx_feed(source: str, payload: dict[str, Any] | list[dict[str, Any]], default_ttl_days: int = 90) -> list[ThreatIOCCreate]:
    """Normalize AlienVault OTX pulse indicator payloads."""
    records = _coerce_provider_records(payload, "otx")
    for record in records:
        record.setdefault("value", record.get("indicator"))
        record.setdefault("ioc_type", _otx_type(record.get("type")))
        record.setdefault("source_reference", record.get("pulse_id") or record.get("id"))
    return normalize_generic_feed(source, records, default_ttl_days)


def normalize_shodan_feed(source: str, payload: dict[str, Any] | list[dict[str, Any]], default_ttl_days: int = 90) -> list[ThreatIOCCreate]:
    """Normalize Shodan-ready infrastructure indicators."""
    records = _coerce_provider_records(payload, "shodan")
    for record in records:
        record.setdefault("ioc_type", "ip")
        record.setdefault("value", record.get("ip_str") or record.get("ip"))
        record.setdefault("classification", "internet_exposure")
    return normalize_generic_feed(source, records, default_ttl_days)


def normalize_greynoise_feed(source: str, payload: dict[str, Any] | list[dict[str, Any]], default_ttl_days: int = 90) -> list[ThreatIOCCreate]:
    """Normalize GreyNoise-style internet scanner reputation indicators."""
    records = _coerce_provider_records(payload, "greynoise")
    for record in records:
        record.setdefault("ioc_type", "ip")
        record.setdefault("value", record.get("ip"))
        record.setdefault("classification", record.get("classification") or record.get("noise"))
    return normalize_generic_feed(source, records, default_ttl_days)


def _coerce_provider_records(payload: dict[str, Any] | list[dict[str, Any]], provider: str) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [dict(item, source=provider) for item in payload]
    records = payload.get("indicators") or payload.get("data") or payload.get("results") or [payload]
    if isinstance(records, dict):
        records = [records]
    return [dict(item, source=provider) for item in records]


def _otx_type(value: str | None) -> str:
    normalized = (value or "").lower()
    if "ipv4" in normalized or "ipv6" in normalized:
        return "ip"
    if "domain" in normalized or "hostname" in normalized:
        return "domain"
    if "url" in normalized:
        return "url"
    return "hash" if "hash" in normalized or "file" in normalized else "domain"
