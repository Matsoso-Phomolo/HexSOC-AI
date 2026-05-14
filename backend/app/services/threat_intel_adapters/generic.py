"""Generic feed adapter for normalized IOC-like payloads."""

from typing import Any

from app.schemas.threat_ioc import ThreatIOCCreate


def normalize_generic_feed(source: str, payload: dict[str, Any] | list[dict[str, Any]], default_ttl_days: int = 90) -> list[ThreatIOCCreate]:
    """Normalize generic dictionaries containing indicator fields."""
    records = payload if isinstance(payload, list) else payload.get("indicators", [payload])
    indicators: list[ThreatIOCCreate] = []

    for item in records:
        value = item.get("value") or item.get("indicator") or item.get("ioc")
        ioc_type = item.get("ioc_type") or item.get("type")
        if not value or not ioc_type:
            continue
        indicators.append(
            ThreatIOCCreate(
                ioc_type=ioc_type,
                value=str(value),
                source=item.get("source") or source,
                source_reference=item.get("source_reference") or item.get("reference"),
                confidence_score=int(item.get("confidence_score", item.get("confidence", 50)) or 50),
                risk_score=int(item.get("risk_score", item.get("risk", 50)) or 50),
                severity=item.get("severity") or "medium",
                tags=_as_list(item.get("tags")),
                classification=item.get("classification") or item.get("threat_type"),
                description=item.get("description"),
                ttl_days=default_ttl_days,
                raw_payload=item,
            )
        )

    return indicators


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]
