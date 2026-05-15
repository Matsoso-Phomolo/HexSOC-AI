"""Standardized graph edge construction for investigation relationships."""

from __future__ import annotations

from datetime import datetime
from typing import Any


SEVERITY_WEIGHT = {"info": 1, "low": 2, "medium": 4, "high": 7, "critical": 10}


def build_relationship(
    source_id: str,
    target_id: str,
    relationship_type: str,
    *,
    weight: int = 1,
    confidence: int = 50,
    severity: str = "info",
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a graph-safe weighted edge."""
    normalized_type = relationship_type.strip().upper()
    return {
        "id": f"edge:{source_id}:{target_id}:{normalized_type}",
        "source_id": source_id,
        "target_id": target_id,
        "source": source_id,
        "target": target_id,
        "relationship_type": normalized_type,
        "relationship": normalized_type.lower(),
        "weight": max(1, min(weight, 100)),
        "confidence": max(0, min(confidence, 100)),
        "severity": severity or "info",
        "first_seen": _iso(first_seen),
        "last_seen": _iso(last_seen),
        "metadata": metadata or {},
    }


def ioc_edge_weight(*, severity: str, confidence: int, source_count: int) -> int:
    """Compute bounded relationship weight from IOC context."""
    severity_component = SEVERITY_WEIGHT.get((severity or "info").lower(), 1) * 6
    confidence_component = int(max(0, min(confidence, 100)) / 4)
    source_component = min(max(source_count, 1) * 4, 20)
    return min(100, severity_component + confidence_component + source_component)


def dedupe_relationships(relationships: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate edges by stable id, keeping the highest-weight relationship."""
    deduped: dict[str, dict[str, Any]] = {}
    for relationship in relationships:
        edge_id = relationship["id"]
        existing = deduped.get(edge_id)
        if not existing or relationship.get("weight", 0) > existing.get("weight", 0):
            deduped[edge_id] = relationship
    return list(deduped.values())


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None
