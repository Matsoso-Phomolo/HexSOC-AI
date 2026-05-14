"""Threat Intelligence Feed Integrator service layer."""

from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import models
from app.schemas.threat_ioc import ThreatIOCCreate
from app.services.activity_service import add_activity
from app.services.threat_intel_adapters import normalize_feed_payload


IOC_TYPES = {"ip", "domain", "url", "hash"}


def ingest_iocs(
    db: Session,
    indicators: list[ThreatIOCCreate],
    *,
    actor_username: str | None = None,
    actor_role: str | None = None,
) -> dict[str, Any]:
    """Normalize, deduplicate, and persist threat indicators."""
    created = 0
    updated = 0
    skipped = 0
    stored: list[models.ThreatIOC] = []

    for indicator in indicators:
        normalized_type, normalized_value = normalize_ioc(indicator.ioc_type, indicator.value)
        if not normalized_value:
            skipped += 1
            continue

        expires_at = indicator.expires_at or _expiry_from_ttl(indicator.ttl_days)
        existing = (
            db.query(models.ThreatIOC)
            .filter(
                models.ThreatIOC.source == indicator.source,
                models.ThreatIOC.ioc_type == normalized_type,
                models.ThreatIOC.normalized_value == normalized_value,
            )
            .first()
        )

        if existing:
            _apply_ioc_update(existing, indicator, normalized_type, normalized_value, expires_at)
            updated += 1
            stored.append(existing)
            continue

        ioc = models.ThreatIOC(
            ioc_type=normalized_type,
            value=indicator.value.strip(),
            normalized_value=normalized_value,
            source=indicator.source.strip().lower(),
            source_reference=indicator.source_reference,
            confidence_score=indicator.confidence_score,
            risk_score=indicator.risk_score,
            severity=_severity_from_score(indicator.risk_score, indicator.severity),
            tags=indicator.tags,
            classification=indicator.classification,
            description=indicator.description,
            first_seen_at=indicator.first_seen_at,
            last_seen_at=indicator.last_seen_at or datetime.now(timezone.utc),
            expires_at=expires_at,
            is_active=True,
            raw_payload=indicator.raw_payload,
        )
        db.add(ioc)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            existing = (
                db.query(models.ThreatIOC)
                .filter(
                    models.ThreatIOC.source == indicator.source,
                    models.ThreatIOC.ioc_type == normalized_type,
                    models.ThreatIOC.normalized_value == normalized_value,
                )
                .first()
            )
            if existing:
                _apply_ioc_update(existing, indicator, normalized_type, normalized_value, expires_at)
                updated += 1
                stored.append(existing)
            else:
                skipped += 1
            continue
        created += 1
        stored.append(ioc)

    add_activity(
        db,
        action="threat_ioc_ingested",
        entity_type="threat_ioc",
        entity_id=None,
        message=f"Threat Intel Feed Integrator processed {len(indicators)} indicators: {created} created, {updated} updated, {skipped} skipped.",
        severity="info",
        actor_username=actor_username,
        actor_role=actor_role,
    )
    db.commit()
    for ioc in stored:
        db.refresh(ioc)

    return {
        "received": len(indicators),
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "indicators": stored,
    }


def normalize_and_ingest_feed(
    db: Session,
    source: str,
    payload: dict[str, Any] | list[dict[str, Any]],
    *,
    default_ttl_days: int = 90,
    actor_username: str | None = None,
    actor_role: str | None = None,
) -> dict[str, Any]:
    """Normalize a provider payload and ingest resulting IOCs."""
    indicators = normalize_feed_payload(source, payload, default_ttl_days)
    return ingest_iocs(db, indicators, actor_username=actor_username, actor_role=actor_role)


def correlate_iocs(db: Session) -> dict[str, int]:
    """Create IOC links to existing alerts, events, and assets."""
    expired = expire_iocs(db)
    active_iocs = (
        db.query(models.ThreatIOC)
        .filter(models.ThreatIOC.is_active.is_(True))
        .order_by(models.ThreatIOC.risk_score.desc(), models.ThreatIOC.id.desc())
        .limit(1000)
        .all()
    )
    created = 0
    existing = 0

    for ioc in active_iocs:
        matches = _find_ioc_matches(db, ioc)
        for entity_type, entity_id in matches:
            link = (
                db.query(models.ThreatIOCLink)
                .filter(
                    models.ThreatIOCLink.ioc_id == ioc.id,
                    models.ThreatIOCLink.entity_type == entity_type,
                    models.ThreatIOCLink.entity_id == entity_id,
                    models.ThreatIOCLink.relationship == "correlated_with",
                )
                .first()
            )
            if link:
                existing += 1
                continue
            db.add(
                models.ThreatIOCLink(
                    ioc_id=ioc.id,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    relationship="correlated_with",
                    confidence_score=ioc.confidence_score,
                )
            )
            created += 1

    add_activity(
        db,
        action="threat_ioc_correlated",
        entity_type="threat_ioc",
        entity_id=None,
        message=f"IOC correlation created {created} links across alerts, events, and assets.",
        severity="info",
    )
    db.commit()
    return {
        "active_iocs_checked": len(active_iocs),
        "links_created": created,
        "links_existing": existing,
        "expired_iocs_deactivated": expired,
    }


def expire_iocs(db: Session) -> int:
    """Deactivate expired IOCs without deleting feed history."""
    now = datetime.now(timezone.utc)
    expired = (
        db.query(models.ThreatIOC)
        .filter(models.ThreatIOC.is_active.is_(True), models.ThreatIOC.expires_at.isnot(None), models.ThreatIOC.expires_at < now)
        .all()
    )
    for ioc in expired:
        ioc.is_active = False
    return len(expired)


def normalize_ioc(ioc_type: str, value: str) -> tuple[str, str]:
    """Normalize IOC type and value for deduplication."""
    normalized_type = (ioc_type or "").lower().strip()
    raw = (value or "").strip()
    if normalized_type not in IOC_TYPES or not raw:
        return normalized_type, ""
    if normalized_type == "domain":
        return normalized_type, raw.lower().rstrip(".")
    if normalized_type == "url":
        parsed = urlparse(raw)
        scheme = (parsed.scheme or "http").lower()
        host = (parsed.netloc or parsed.path.split("/", 1)[0]).lower()
        path = parsed.path if parsed.netloc else "/" + "/".join(parsed.path.split("/")[1:])
        return normalized_type, f"{scheme}://{host}{path}".rstrip("/")
    if normalized_type == "hash":
        return normalized_type, raw.lower()
    return normalized_type, raw.lower()


def _apply_ioc_update(
    ioc: models.ThreatIOC,
    indicator: ThreatIOCCreate,
    normalized_type: str,
    normalized_value: str,
    expires_at: datetime | None,
) -> None:
    ioc.ioc_type = normalized_type
    ioc.value = indicator.value.strip()
    ioc.normalized_value = normalized_value
    ioc.confidence_score = max(ioc.confidence_score or 0, indicator.confidence_score)
    ioc.risk_score = max(ioc.risk_score or 0, indicator.risk_score)
    ioc.severity = _severity_from_score(ioc.risk_score, indicator.severity)
    ioc.tags = sorted(set((ioc.tags or []) + indicator.tags))
    ioc.classification = indicator.classification or ioc.classification
    ioc.description = indicator.description or ioc.description
    ioc.source_reference = indicator.source_reference or ioc.source_reference
    ioc.last_seen_at = indicator.last_seen_at or datetime.now(timezone.utc)
    ioc.expires_at = expires_at or ioc.expires_at
    ioc.is_active = True
    ioc.raw_payload = indicator.raw_payload or ioc.raw_payload


def _find_ioc_matches(db: Session, ioc: models.ThreatIOC) -> set[tuple[str, int]]:
    value = ioc.normalized_value
    matches: set[tuple[str, int]] = set()
    if ioc.ioc_type == "ip":
        for event in db.query(models.SecurityEvent).filter(or_(models.SecurityEvent.source_ip == value, models.SecurityEvent.destination_ip == value)).limit(500):
            matches.add(("event", event.id))
        for asset in db.query(models.Asset).filter(models.Asset.ip_address == value).limit(200):
            matches.add(("asset", asset.id))
        for alert in db.query(models.Alert).filter(models.Alert.detection_rule.contains(value)).limit(200):
            matches.add(("alert", alert.id))
    elif ioc.ioc_type in {"domain", "url", "hash"}:
        pattern = f"%{value}%"
        for event in db.query(models.SecurityEvent).filter(models.SecurityEvent.raw_message.ilike(pattern)).limit(500):
            matches.add(("event", event.id))
        for alert in db.query(models.Alert).filter(models.Alert.description.ilike(pattern)).limit(200):
            matches.add(("alert", alert.id))
    return matches


def _expiry_from_ttl(ttl_days: int | None) -> datetime | None:
    if not ttl_days:
        return None
    return datetime.now(timezone.utc) + timedelta(days=ttl_days)


def _severity_from_score(score: int, fallback: str) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return fallback or "low"
