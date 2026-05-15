"""IOC correlation foundation for alerts, events, assets, and graph relationships."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.db import models
from app.services.ioc_normalizer import NormalizedIOC, normalize_ioc_value


def correlate_indicators(db: Session, values: list[str], limit: int = 100) -> dict[str, Any]:
    """Correlate raw indicator values against stored active IOCs."""
    results = []
    links = []
    risk_amplification = 0

    for value in values[:limit]:
        normalized = normalize_ioc_value(value)
        if not normalized.is_valid:
            results.append({"input": value, "matched": False, "reason": normalized.reason})
            continue

        matches = _lookup_iocs(db, normalized)
        relationship_payloads = [_relationship_payload(ioc) for ioc in matches]
        risk_amplification += sum(_risk_boost(ioc) for ioc in matches)
        links.extend(relationship_payloads)
        results.append(
            {
                "input": value,
                "normalized": asdict(normalized),
                "matched": bool(matches),
                "matches": [_ioc_payload(ioc) for ioc in matches],
                "graph_relationships": relationship_payloads,
            }
        )

    return {
        "inputs_checked": len(values[:limit]),
        "matches_found": sum(1 for result in results if result.get("matched")),
        "risk_amplification": min(risk_amplification, 100),
        "results": results,
        "graph_relationships": links,
    }


def correlate_stored_iocs(db: Session, limit: int = 1000) -> dict[str, int]:
    """Create persistent IOC links to matching SOC entities."""
    active_iocs = (
        db.query(models.ThreatIOC)
        .filter(models.ThreatIOC.is_active.is_(True))
        .order_by(models.ThreatIOC.risk_score.desc(), models.ThreatIOC.id.desc())
        .limit(limit)
        .all()
    )
    created = 0
    existing = 0

    for ioc in active_iocs:
        for entity_type, entity_id in _find_entity_matches(db, ioc):
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

    return {
        "active_iocs_checked": len(active_iocs),
        "links_created": created,
        "links_existing": existing,
    }


def _lookup_iocs(db: Session, normalized: NormalizedIOC) -> list[models.ThreatIOC]:
    return (
        db.query(models.ThreatIOC)
        .filter(
            models.ThreatIOC.is_active.is_(True),
            models.ThreatIOC.ioc_type == normalized.ioc_type,
            models.ThreatIOC.normalized_value == normalized.normalized_value,
        )
        .order_by(models.ThreatIOC.risk_score.desc(), models.ThreatIOC.confidence_score.desc())
        .limit(20)
        .all()
    )


def _find_entity_matches(db: Session, ioc: models.ThreatIOC) -> set[tuple[str, int]]:
    value = ioc.normalized_value
    matches: set[tuple[str, int]] = set()

    if ioc.ioc_type == "ip":
        for event in db.query(models.SecurityEvent).filter(or_(models.SecurityEvent.source_ip == value, models.SecurityEvent.destination_ip == value)).limit(500):
            matches.add(("event", event.id))
        for asset in db.query(models.Asset).filter(models.Asset.ip_address == value).limit(200):
            matches.add(("asset", asset.id))
    elif ioc.ioc_type in {"domain", "url", "hash", "email", "cve"}:
        pattern = f"%{value}%"
        for event in db.query(models.SecurityEvent).filter(models.SecurityEvent.raw_message.ilike(pattern)).limit(500):
            matches.add(("event", event.id))
        for alert in db.query(models.Alert).filter(models.Alert.description.ilike(pattern)).limit(200):
            matches.add(("alert", alert.id))

    return matches


def _ioc_payload(ioc: models.ThreatIOC) -> dict[str, Any]:
    return {
        "id": ioc.id,
        "ioc_type": ioc.ioc_type,
        "value": ioc.value,
        "normalized_value": ioc.normalized_value,
        "severity": ioc.severity,
        "confidence_score": ioc.confidence_score,
        "risk_score": ioc.risk_score,
        "sources": ioc.sources or [ioc.source],
        "tags": ioc.tags or [],
    }


def _relationship_payload(ioc: models.ThreatIOC) -> dict[str, Any]:
    return {
        "source": f"ioc:{ioc.id}",
        "target": f"{ioc.ioc_type}:{ioc.normalized_value}",
        "relationship": "threat_intel_match",
        "weight": max(1, int((ioc.risk_score or 50) / 20)),
        "confidence_score": ioc.confidence_score,
    }


def _risk_boost(ioc: models.ThreatIOC) -> int:
    if ioc.severity == "critical":
        return 30
    if ioc.severity == "high":
        return 20
    if ioc.severity == "medium":
        return 10
    return 5
