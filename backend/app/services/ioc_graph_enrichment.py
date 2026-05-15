"""Convert IOC correlation matches into graph-native nodes and weighted relationships."""

from __future__ import annotations

from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db import models
from app.services.graph_entity_mapper import map_ioc_node, map_platform_entity
from app.services.graph_relationship_builder import build_relationship, dedupe_relationships, ioc_edge_weight
from app.services.ioc_normalizer import normalize_ioc_value


ENTITY_MODELS = {
    "alert": models.Alert,
    "event": models.SecurityEvent,
    "asset": models.Asset,
    "incident": models.Incident,
}


RELATIONSHIP_BY_ENTITY = {
    "alert": "MATCHES_IOC",
    "event": "OBSERVED_IN_EVENT",
    "asset": "ASSOCIATED_WITH_IOC",
    "incident": "PART_OF_INCIDENT",
}


def enrich_entity_with_iocs(
    db: Session,
    *,
    entity_type: str,
    entity_id: int,
    indicators: list[str],
    limit: int = 100,
) -> dict[str, Any]:
    """Build bounded IOC graph enrichment for a single SOC entity."""
    normalized_entity_type = entity_type.strip().lower()
    entity = _load_entity(db, normalized_entity_type, entity_id)
    entity_node = map_platform_entity(normalized_entity_type, entity)

    ioc_nodes: dict[str, dict[str, Any]] = {}
    relationships = []
    links_created = 0
    risk_amplification = 0

    for raw_indicator in indicators[:limit]:
        normalized = normalize_ioc_value(raw_indicator)
        if not normalized.is_valid:
            continue
        matches = _lookup_iocs(db, normalized.ioc_type, normalized.normalized_value, limit=20)
        for ioc in matches:
            ioc_node = map_ioc_node(ioc)
            ioc_nodes[ioc_node["id"]] = ioc_node
            relationship_type = RELATIONSHIP_BY_ENTITY.get(normalized_entity_type, "MATCHES_IOC")
            source_count = ioc.source_count or len(ioc.sources or [ioc.source])
            weight = ioc_edge_weight(severity=ioc.severity, confidence=ioc.confidence_score, source_count=source_count)
            relationships.append(
                build_relationship(
                    entity_node["id"],
                    ioc_node["id"],
                    relationship_type,
                    weight=weight,
                    confidence=ioc.confidence_score,
                    severity=ioc.severity,
                    first_seen=ioc.first_seen_at,
                    last_seen=ioc.last_seen_at,
                    metadata={
                        "ioc_id": ioc.id,
                        "ioc_type": ioc.ioc_type,
                        "normalized_value": ioc.normalized_value,
                        "source_count": source_count,
                        "sources": ioc.sources or [ioc.source],
                    },
                )
            )
            if _ensure_ioc_link(db, ioc, normalized_entity_type, entity_id, relationship_type):
                links_created += 1
            risk_amplification += _risk_amplification(ioc)

    relationships = dedupe_relationships(relationships)
    db.commit()
    return {
        "entity_node": entity_node,
        "ioc_nodes": list(ioc_nodes.values())[:limit],
        "relationships": relationships[:limit],
        "summary": {
            "matched_iocs": len(ioc_nodes),
            "relationships_created": links_created,
            "max_weight": max((relationship["weight"] for relationship in relationships), default=0),
            "risk_amplification": min(risk_amplification, 100),
        },
    }


def relationship_summary(db: Session, limit: int = 100) -> dict[str, Any]:
    """Return bounded IOC relationship operational summary."""
    limit = max(1, min(limit, 500))
    total_relationships = db.query(models.ThreatIOCLink).count()
    by_entity = (
        db.query(models.ThreatIOCLink.entity_type, func.count(models.ThreatIOCLink.id))
        .group_by(models.ThreatIOCLink.entity_type)
        .order_by(func.count(models.ThreatIOCLink.id).desc())
        .limit(20)
        .all()
    )
    recent = (
        db.query(models.ThreatIOCLink)
        .order_by(models.ThreatIOCLink.id.desc())
        .limit(limit)
        .all()
    )
    return {
        "total_relationships": total_relationships,
        "by_entity_type": [{"entity_type": entity_type, "count": count} for entity_type, count in by_entity],
        "recent_relationships": [_link_payload(link) for link in recent],
    }


def graph_ioc_relationships(db: Session, limit: int = 100) -> dict[str, Any]:
    """Return graph-safe IOC relationship payload without full graph expansion."""
    limit = max(1, min(limit, 500))
    links = (
        db.query(models.ThreatIOCLink)
        .order_by(models.ThreatIOCLink.id.desc())
        .limit(limit)
        .all()
    )
    ioc_ids = {link.ioc_id for link in links}
    iocs = {ioc.id: ioc for ioc in db.query(models.ThreatIOC).filter(models.ThreatIOC.id.in_(ioc_ids)).limit(limit).all()} if ioc_ids else {}

    nodes: dict[str, dict[str, Any]] = {}
    relationships = []
    for link in links:
        ioc = iocs.get(link.ioc_id)
        if not ioc:
            continue
        ioc_node = map_ioc_node(ioc)
        entity_node = _entity_reference_node(link.entity_type, link.entity_id)
        nodes[ioc_node["id"]] = ioc_node
        nodes[entity_node["id"]] = entity_node
        source_count = ioc.source_count or len(ioc.sources or [ioc.source])
        relationships.append(
            build_relationship(
                entity_node["id"],
                ioc_node["id"],
                link.relationship.upper(),
                weight=ioc_edge_weight(severity=ioc.severity, confidence=link.confidence_score, source_count=source_count),
                confidence=link.confidence_score,
                severity=ioc.severity,
                first_seen=ioc.first_seen_at,
                last_seen=ioc.last_seen_at,
                metadata={"ioc_id": ioc.id, "link_id": link.id},
            )
        )

    relationships = dedupe_relationships(relationships)
    return {
        "nodes": list(nodes.values()),
        "edges": relationships,
        "summary": {
            "nodes": len(nodes),
            "edges": len(relationships),
            "high_risk_relationships": sum(1 for edge in relationships if edge["severity"] in {"high", "critical"}),
        },
    }


def _load_entity(db: Session, entity_type: str, entity_id: int) -> Any:
    model = ENTITY_MODELS.get(entity_type)
    if not model:
        raise ValueError(f"Unsupported entity type: {entity_type}")
    entity = db.get(model, entity_id)
    if not entity:
        raise LookupError(f"{entity_type} {entity_id} was not found")
    return entity


def _lookup_iocs(db: Session, ioc_type: str, normalized_value: str, limit: int) -> list[models.ThreatIOC]:
    return (
        db.query(models.ThreatIOC)
        .filter(
            models.ThreatIOC.is_active.is_(True),
            models.ThreatIOC.ioc_type == ioc_type,
            models.ThreatIOC.normalized_value == normalized_value,
        )
        .order_by(models.ThreatIOC.risk_score.desc(), models.ThreatIOC.confidence_score.desc())
        .limit(limit)
        .all()
    )


def _ensure_ioc_link(db: Session, ioc: models.ThreatIOC, entity_type: str, entity_id: int, relationship: str) -> bool:
    normalized_relationship = relationship.lower()
    existing = (
        db.query(models.ThreatIOCLink)
        .filter(
            models.ThreatIOCLink.ioc_id == ioc.id,
            models.ThreatIOCLink.entity_type == entity_type,
            models.ThreatIOCLink.entity_id == entity_id,
            models.ThreatIOCLink.relationship == normalized_relationship,
        )
        .first()
    )
    if existing:
        existing.confidence_score = max(existing.confidence_score or 0, ioc.confidence_score or 0)
        return False
    db.add(
        models.ThreatIOCLink(
            ioc_id=ioc.id,
            entity_type=entity_type,
            entity_id=entity_id,
            relationship=normalized_relationship,
            confidence_score=ioc.confidence_score,
        )
    )
    return True


def _entity_reference_node(entity_type: str, entity_id: int) -> dict[str, Any]:
    return {
        "id": f"{entity_type}:{entity_id}",
        "label": f"{entity_type} {entity_id}",
        "type": entity_type,
        "severity": "info",
        "metadata": {"id": entity_id},
    }


def _link_payload(link: models.ThreatIOCLink) -> dict[str, Any]:
    return {
        "id": link.id,
        "ioc_id": link.ioc_id,
        "entity_type": link.entity_type,
        "entity_id": link.entity_id,
        "relationship": link.relationship,
        "confidence_score": link.confidence_score,
        "created_at": link.created_at,
    }


def _risk_amplification(ioc: models.ThreatIOC) -> int:
    if ioc.severity == "critical":
        return 30
    if ioc.severity == "high":
        return 20
    if ioc.severity == "medium":
        return 10
    return 5
