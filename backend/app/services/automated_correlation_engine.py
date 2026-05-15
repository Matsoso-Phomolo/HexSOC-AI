"""Automated local IOC extraction and threat-intelligence correlation pipeline."""

from __future__ import annotations

from statistics import mean
from typing import Any

from sqlalchemy.orm import Session

from app.db import models
from app.services.ioc_extractor import extract_iocs
from app.services.ioc_graph_enrichment import enrich_entity_with_iocs

try:
    from app.services.threat_intel_provider_orchestrator import enrich_indicators
except ImportError:  # pragma: no cover - keeps local correlation usable if providers are disabled.
    enrich_indicators = None


CLASSIFICATION = [(75, "critical"), (50, "malicious"), (25, "suspicious"), (0, "safe")]


def auto_correlate_entity(
    db: Session,
    *,
    entity_type: str,
    payload: dict[str, Any],
    entity_id: int | None = None,
    use_providers: bool = False,
    persist_relationships: bool = True,
    limit: int = 100,
) -> dict[str, Any]:
    """Extract IOCs, correlate locally, optionally enrich, and build graph-ready relationships."""
    limit = max(1, min(limit, 100))
    extracted = extract_iocs(payload, limit=limit)
    indicators = [item["normalized_value"] for item in extracted]
    local_matches = _lookup_local_matches(db, extracted)
    provider_result = _provider_enrich(db, indicators, use_providers)
    graph_result = _graph_enrich(db, entity_type, entity_id, indicators, persist_relationships)
    risk = _risk_score(local_matches, provider_result, graph_result)

    return {
        "entity_type": entity_type,
        "entity_id": str(entity_id) if entity_id is not None else None,
        "indicators_extracted": len(extracted),
        "local_matches": len(local_matches),
        "provider_matches": provider_result["provider_matches"],
        "relationships_created": graph_result.get("summary", {}).get("relationships_created", 0),
        "risk_amplification": risk,
        "max_confidence": max([ioc.confidence_score or 0 for ioc in local_matches] + [provider_result["max_confidence"], 0]),
        "classification": _classify(risk),
        "matched_iocs": [_ioc_payload(ioc) for ioc in local_matches[:25]],
        "relationships": graph_result.get("relationships", [])[:50],
        "provider_errors": provider_result["provider_errors"],
    }


def correlation_summary(db: Session, limit: int = 100) -> dict[str, Any]:
    """Return bounded operational summary for IOC correlation state."""
    limit = max(1, min(limit, 500))
    total = db.query(models.ThreatIOCLink).count()
    recent_links = db.query(models.ThreatIOCLink).order_by(models.ThreatIOCLink.id.desc()).limit(limit).all()
    ioc_ids = {link.ioc_id for link in recent_links}
    iocs = {ioc.id: ioc for ioc in db.query(models.ThreatIOC).filter(models.ThreatIOC.id.in_(ioc_ids)).limit(limit).all()} if ioc_ids else {}
    risks = [_risk_from_ioc(iocs[link.ioc_id]) for link in recent_links if link.ioc_id in iocs]
    type_counts: dict[str, int] = {}
    entity_counts: dict[str, int] = {}
    high_risk = []
    for link in recent_links:
        ioc = iocs.get(link.ioc_id)
        if not ioc:
            continue
        type_counts[ioc.ioc_type] = type_counts.get(ioc.ioc_type, 0) + 1
        entity_key = f"{link.entity_type}:{link.entity_id}"
        entity_counts[entity_key] = entity_counts.get(entity_key, 0) + 1
        risk = _risk_from_ioc(ioc)
        if risk >= 50:
            high_risk.append({"entity": entity_key, "ioc": ioc.normalized_value, "ioc_type": ioc.ioc_type, "risk": risk})

    return {
        "total_correlations": total,
        "recent_high_risk_correlations": sorted(high_risk, key=lambda item: item["risk"], reverse=True)[:10],
        "top_matched_ioc_types": _top_counts(type_counts),
        "top_related_entities": _top_counts(entity_counts),
        "average_risk_amplification": round(mean(risks), 2) if risks else 0,
    }


def risk_hotspots(db: Session, limit: int = 100) -> list[dict[str, Any]]:
    """Return highest-risk IOC/entity relationships without graph expansion."""
    limit = max(1, min(limit, 500))
    links = db.query(models.ThreatIOCLink).order_by(models.ThreatIOCLink.id.desc()).limit(limit).all()
    ioc_ids = {link.ioc_id for link in links}
    iocs = {ioc.id: ioc for ioc in db.query(models.ThreatIOC).filter(models.ThreatIOC.id.in_(ioc_ids)).limit(limit).all()} if ioc_ids else {}
    hotspots = []
    for link in links:
        ioc = iocs.get(link.ioc_id)
        if not ioc:
            continue
        hotspots.append(
            {
                "entity_type": link.entity_type,
                "entity_id": link.entity_id,
                "ioc_id": ioc.id,
                "ioc_type": ioc.ioc_type,
                "ioc": ioc.normalized_value,
                "severity": ioc.severity,
                "confidence_score": ioc.confidence_score,
                "risk_amplification": _risk_from_ioc(ioc),
            }
        )
    return sorted(hotspots, key=lambda item: item["risk_amplification"], reverse=True)[:limit]


def _lookup_local_matches(db: Session, extracted: list[dict[str, Any]]) -> list[models.ThreatIOC]:
    matches: dict[int, models.ThreatIOC] = {}
    for item in extracted:
        for ioc in (
            db.query(models.ThreatIOC)
            .filter(
                models.ThreatIOC.ioc_type == item["ioc_type"],
                models.ThreatIOC.normalized_value == item["normalized_value"],
            )
            .order_by(models.ThreatIOC.is_active.desc(), models.ThreatIOC.risk_score.desc())
            .limit(10)
        ):
            matches[ioc.id] = ioc
    return sorted(matches.values(), key=lambda ioc: (ioc.risk_score or 0, ioc.confidence_score or 0), reverse=True)


def _provider_enrich(db: Session, indicators: list[str], use_providers: bool) -> dict[str, Any]:
    if not use_providers or not enrich_indicators or not indicators:
        return {"provider_matches": 0, "max_confidence": 0, "provider_errors": []}
    result = enrich_indicators(db, indicators[:25], persist=False)
    fused = [item.get("fused_result") or {} for item in result.get("results", [])]
    return {
        "provider_matches": sum(1 for item in fused if item.get("matched")),
        "max_confidence": max((item.get("confidence_score") or 0 for item in fused), default=0),
        "provider_errors": result.get("provider_errors", []),
    }


def _graph_enrich(db: Session, entity_type: str, entity_id: int | None, indicators: list[str], persist_relationships: bool) -> dict[str, Any]:
    if not persist_relationships or entity_type == "raw" or entity_id is None or not indicators:
        return {"relationships": [], "summary": {"relationships_created": 0}}
    try:
        return enrich_entity_with_iocs(db, entity_type=entity_type, entity_id=entity_id, indicators=indicators[:100])
    except (LookupError, ValueError):
        return {"relationships": [], "summary": {"relationships_created": 0}}


def _risk_score(local_matches: list[models.ThreatIOC], provider_result: dict[str, Any], graph_result: dict[str, Any]) -> int:
    score = 0
    if local_matches:
        score += 20
    for ioc in local_matches[:10]:
        score += _risk_from_ioc(ioc)
    if provider_result["provider_matches"]:
        score += min(40, provider_result["provider_matches"] * 20)
    if graph_result.get("summary", {}).get("relationships_created", 0) > 1:
        score += 10
    return min(score, 100)


def _risk_from_ioc(ioc: models.ThreatIOC) -> int:
    score = 0
    if ioc.severity == "critical":
        score += 40
    elif ioc.severity == "high":
        score += 25
    elif ioc.severity == "medium":
        score += 10
    if (ioc.source_count or 0) > 1:
        score += 10
    if (ioc.confidence_score or 0) >= 80:
        score += 15
    if not ioc.is_active:
        score -= 20
    return max(0, min(score, 100))


def _classify(score: int) -> str:
    for threshold, label in CLASSIFICATION:
        if score >= threshold:
            return label
    return "safe"


def _ioc_payload(ioc: models.ThreatIOC) -> dict[str, Any]:
    return {
        "id": ioc.id,
        "ioc_type": ioc.ioc_type,
        "normalized_value": ioc.normalized_value,
        "severity": ioc.severity,
        "confidence_score": ioc.confidence_score,
        "risk_score": ioc.risk_score,
        "source_count": ioc.source_count,
        "sources": ioc.sources or [ioc.source],
        "is_active": ioc.is_active,
    }


def _top_counts(counts: dict[str, int]) -> list[dict[str, Any]]:
    return [{"key": key, "count": count} for key, count in sorted(counts.items(), key=lambda item: item[1], reverse=True)[:10]]
