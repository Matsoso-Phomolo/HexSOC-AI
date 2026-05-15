"""IOC deduplication and merge behavior for feed ingestion."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.db import models
from app.schemas.threat_ioc import ThreatIOCCreate
from app.services.ioc_normalizer import NormalizedIOC, normalize_ioc_value


def upsert_ioc(db: Session, indicator: ThreatIOCCreate) -> tuple[str, models.ThreatIOC | None, str | None]:
    """Normalize, deduplicate, and upsert a single IOC record."""
    normalized = normalize_ioc_value(indicator.value, indicator.ioc_type)
    if not normalized.is_valid:
        return "skipped", None, normalized.reason

    existing = _find_existing_ioc(db, normalized)
    now = datetime.now(timezone.utc)
    expires_at = indicator.expires_at

    if existing:
        _merge_ioc(existing, indicator, normalized, now, expires_at)
        return "updated", existing, None

    ioc = models.ThreatIOC(
        ioc_type=normalized.ioc_type,
        value=indicator.value.strip(),
        normalized_value=normalized.normalized_value,
        fingerprint=normalized.fingerprint,
        source=indicator.source.strip().lower(),
        sources=_merge_sources([], indicator.source),
        source_count=1,
        source_reference=indicator.source_reference,
        confidence_score=indicator.confidence_score,
        risk_score=indicator.risk_score,
        severity=_highest_severity(indicator.severity, _severity_from_score(indicator.risk_score)),
        tags=sorted(set(indicator.tags)),
        classification=indicator.classification,
        description=indicator.description,
        first_seen_at=indicator.first_seen_at or now,
        last_seen_at=indicator.last_seen_at or now,
        expires_at=expires_at,
        is_active=True,
        raw_payload=indicator.raw_payload,
        raw_context=_build_raw_context(indicator),
    )
    db.add(ioc)
    db.flush()
    return "created", ioc, None


def _find_existing_ioc(db: Session, normalized: NormalizedIOC) -> models.ThreatIOC | None:
    query = db.query(models.ThreatIOC)
    if hasattr(models.ThreatIOC, "fingerprint"):
        existing = query.filter(models.ThreatIOC.fingerprint == normalized.fingerprint).first()
        if existing:
            return existing
    return query.filter(
        models.ThreatIOC.ioc_type == normalized.ioc_type,
        models.ThreatIOC.normalized_value == normalized.normalized_value,
    ).first()


def _merge_ioc(
    ioc: models.ThreatIOC,
    indicator: ThreatIOCCreate,
    normalized: NormalizedIOC,
    now: datetime,
    expires_at: datetime | None,
) -> None:
    ioc.ioc_type = normalized.ioc_type
    ioc.value = indicator.value.strip()
    ioc.normalized_value = normalized.normalized_value
    ioc.fingerprint = normalized.fingerprint
    ioc.source = ioc.source or indicator.source.strip().lower()
    ioc.sources = _merge_sources(ioc.sources or [], indicator.source)
    ioc.source_count = len(ioc.sources or [])
    ioc.confidence_score = max(ioc.confidence_score or 0, indicator.confidence_score)
    ioc.risk_score = max(ioc.risk_score or 0, indicator.risk_score)
    ioc.severity = _highest_severity(ioc.severity, indicator.severity, _severity_from_score(ioc.risk_score))
    ioc.tags = sorted(set((ioc.tags or []) + indicator.tags))
    ioc.classification = indicator.classification or ioc.classification
    ioc.description = indicator.description or ioc.description
    ioc.source_reference = indicator.source_reference or ioc.source_reference
    ioc.first_seen_at = min(filter(None, [ioc.first_seen_at, indicator.first_seen_at, now]))
    ioc.last_seen_at = max(filter(None, [ioc.last_seen_at, indicator.last_seen_at, now]))
    ioc.expires_at = _max_datetime(ioc.expires_at, expires_at)
    ioc.is_active = True
    ioc.raw_payload = indicator.raw_payload or ioc.raw_payload
    ioc.raw_context = _merge_context(ioc.raw_context, indicator)


def _merge_sources(existing: list[str], source: str) -> list[str]:
    normalized_source = (source or "manual").strip().lower()
    return sorted(set(existing + [normalized_source]))


def _build_raw_context(indicator: ThreatIOCCreate) -> dict[str, Any]:
    return {
        "sources": [
            {
                "source": indicator.source.strip().lower(),
                "source_reference": indicator.source_reference,
                "raw_payload": indicator.raw_payload,
                "raw_context": indicator.raw_context,
            }
        ]
    }


def _merge_context(existing: dict[str, Any] | None, indicator: ThreatIOCCreate) -> dict[str, Any]:
    context = existing or {"sources": []}
    sources = context.get("sources") if isinstance(context.get("sources"), list) else []
    sources.append(
        {
            "source": indicator.source.strip().lower(),
            "source_reference": indicator.source_reference,
            "raw_payload": indicator.raw_payload,
            "raw_context": indicator.raw_context,
        }
    )
    context["sources"] = sources[-20:]
    return context


def _severity_from_score(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _highest_severity(*values: str | None) -> str:
    ranking = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return max((value or "low" for value in values), key=lambda value: ranking.get(value, 0))


def _max_datetime(left: datetime | None, right: datetime | None) -> datetime | None:
    if left and right:
        return max(left, right)
    return left or right
