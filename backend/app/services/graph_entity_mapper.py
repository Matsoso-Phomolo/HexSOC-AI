"""Stable graph identity mapping for HexSOC platform entities."""

from __future__ import annotations

from typing import Any

from app.db import models


def graph_node_id(entity_type: str, identifier: str | int) -> str:
    """Build a stable graph node identifier."""
    return f"{entity_type.strip().lower()}:{identifier}"


def map_platform_entity(entity_type: str, entity: Any) -> dict[str, Any]:
    """Map a persisted SOC entity into a graph-safe node."""
    normalized_type = entity_type.strip().lower()
    if normalized_type == "alert":
        return _node(
            graph_node_id("alert", entity.id),
            entity.title or f"Alert {entity.id}",
            "alert",
            entity.severity,
            {
                "id": entity.id,
                "status": entity.status,
                "event_id": entity.event_id,
                "detection_rule": entity.detection_rule,
                "mitre_tactic": entity.mitre_tactic,
                "mitre_technique": entity.mitre_technique,
                "mitre_technique_id": entity.mitre_technique_id,
            },
        )
    if normalized_type == "event":
        return _node(
            graph_node_id("event", entity.id),
            entity.event_type or f"Event {entity.id}",
            "event",
            entity.severity,
            {
                "id": entity.id,
                "source_ip": entity.source_ip,
                "destination_ip": entity.destination_ip,
                "username": entity.username,
                "hostname": getattr(entity, "hostname", None),
                "mitre_tactic": entity.mitre_tactic,
                "mitre_technique": entity.mitre_technique,
                "mitre_technique_id": entity.mitre_technique_id,
            },
        )
    if normalized_type == "asset":
        return _node(
            graph_node_id("asset", entity.id),
            entity.hostname or f"Asset {entity.id}",
            "asset",
            entity.criticality or "medium",
            {"id": entity.id, "hostname": entity.hostname, "ip_address": entity.ip_address, "role": entity.role},
        )
    if normalized_type == "incident":
        return _node(
            graph_node_id("incident", entity.id),
            entity.title or f"Incident {entity.id}",
            "incident",
            entity.severity,
            {"id": entity.id, "status": entity.status, "alert_id": entity.alert_id},
        )
    return _node(graph_node_id(normalized_type, getattr(entity, "id", "unknown")), normalized_type, normalized_type, "info", {})


def map_ioc_node(ioc: models.ThreatIOC) -> dict[str, Any]:
    """Map a ThreatIOC record to a stable graph node."""
    stable_id = ioc.fingerprint or f"{ioc.ioc_type}:{ioc.normalized_value}"
    return _node(
        graph_node_id("ioc", stable_id),
        ioc.normalized_value,
        "ioc",
        ioc.severity,
        {
            "id": ioc.id,
            "ioc_type": ioc.ioc_type,
            "value": ioc.value,
            "normalized_value": ioc.normalized_value,
            "fingerprint": ioc.fingerprint,
            "confidence_score": ioc.confidence_score,
            "risk_score": ioc.risk_score,
            "source": ioc.source,
            "sources": ioc.sources or [ioc.source],
            "source_count": ioc.source_count or len(ioc.sources or [ioc.source]),
            "tags": ioc.tags or [],
        },
    )


def map_indicator_node(ioc_type: str, normalized_value: str, severity: str = "info") -> dict[str, Any]:
    """Map a raw indicator identity into a non-persisted graph node."""
    return _node(
        graph_node_id(ioc_type, normalized_value),
        normalized_value,
        ioc_type,
        severity,
        {"ioc_type": ioc_type, "normalized_value": normalized_value},
    )


def _node(node_id: str, label: str, node_type: str, severity: str | None, metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": node_id,
        "label": label,
        "type": node_type,
        "severity": severity or "info",
        "metadata": metadata,
    }
