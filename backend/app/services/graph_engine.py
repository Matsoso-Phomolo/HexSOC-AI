"""Investigation graph builder for SOC relationship analysis."""

from typing import Any

from sqlalchemy.orm import Session

from app.db import models
from app.services.threat_intel_service import get_alert_source_ip


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_SCORE = {"info": 0, "low": 15, "medium": 35, "high": 70, "critical": 90}


def build_investigation_graph(
    db: Session,
    source_ip: str | None = None,
    severity: str | None = None,
    limit: int = 150,
) -> dict[str, Any]:
    """Build source IP, event, alert, incident, asset, and threat intel graph data."""
    limit = max(1, min(limit, 500))
    events = _query_events(db, source_ip, severity, limit)
    alerts = _query_alerts(db, source_ip, severity, limit)
    assets = db.query(models.Asset).all()
    incidents = db.query(models.Incident).all()

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, str]] = {}
    event_ids = {event.id for event in events}
    asset_by_id = {asset.id: asset for asset in assets}
    asset_by_ip = {asset.ip_address: asset for asset in assets if asset.ip_address}

    for event in events:
        if event.source_ip:
            ip_node_id = f"ip:{event.source_ip}"
            _merge_node(
                nodes,
                ip_node_id,
                label=event.source_ip,
                node_type="source_ip",
                severity=event.severity,
                risk_score=max(event.risk_score or 0, SEVERITY_SCORE.get(event.severity, 20)),
                metadata={"source_ip": event.source_ip, "country": event.country, "isp": event.isp},
            )

            event_node_id = f"event:{event.id}"
            _merge_node(
                nodes,
                event_node_id,
                label=event.event_type,
                node_type="event",
                severity=event.severity,
                risk_score=max(event.risk_score or 0, SEVERITY_SCORE.get(event.severity, 20)),
                metadata={
                    "id": event.id,
                    "source": event.source,
                    "source_ip": event.source_ip,
                    "destination_ip": event.destination_ip,
                    "username": event.username,
                    "summary": event.summary,
                },
            )
            _add_edge(edges, ip_node_id, event_node_id, "generated_event")

            for asset in _event_assets(event, asset_by_id, asset_by_ip):
                asset_node_id = f"asset:{asset.id}"
                _merge_node(
                    nodes,
                    asset_node_id,
                    label=asset.hostname,
                    node_type="asset",
                    severity=asset.criticality or "medium",
                    risk_score=SEVERITY_SCORE.get(asset.criticality or "medium", 35),
                    metadata={
                        "id": asset.id,
                        "hostname": asset.hostname,
                        "ip_address": asset.ip_address,
                        "role": asset.role,
                        "status": asset.status,
                    },
                )
                _add_edge(edges, event_node_id, asset_node_id, "affects_asset")

    for alert in alerts:
        alert_node_id = f"alert:{alert.id}"
        _merge_node(
            nodes,
            alert_node_id,
            label=alert.title,
            node_type="alert",
            severity=alert.severity,
            risk_score=max(alert.threat_score or 0, SEVERITY_SCORE.get(alert.severity, 35)),
            metadata={
                "id": alert.id,
                "status": alert.status,
                "source": alert.source,
                "event_id": alert.event_id,
                "detection_rule": alert.detection_rule,
                "threat_source": alert.threat_source,
                "threat_score": alert.threat_score,
                "geo_country": alert.geo_country,
                "isp": alert.isp,
            },
        )

        resolved_source_ip = get_alert_source_ip(db, alert)
        if resolved_source_ip:
            ip_node_id = f"ip:{resolved_source_ip}"
            _merge_node(
                nodes,
                ip_node_id,
                label=resolved_source_ip,
                node_type="source_ip",
                severity=alert.severity,
                risk_score=max(alert.threat_score or 0, SEVERITY_SCORE.get(alert.severity, 35)),
                metadata={"source_ip": resolved_source_ip},
            )
            _add_edge(edges, ip_node_id, alert_node_id, "correlated_with")

        if alert.event_id:
            event_ids.add(alert.event_id)
            _add_edge(edges, f"event:{alert.event_id}", alert_node_id, "triggered_alert")

        if alert.threat_source or alert.threat_score is not None:
            threat_node_id = f"threat_intel:{alert.id}"
            _merge_node(
                nodes,
                threat_node_id,
                label=alert.threat_source or "Threat Intel",
                node_type="threat_intel",
                severity=alert.severity,
                risk_score=alert.threat_score or 0,
                metadata={
                    "provider": alert.threat_source,
                    "threat_score": alert.threat_score,
                    "country": alert.geo_country,
                    "city": alert.geo_city,
                    "isp": alert.isp,
                    "status": alert.enrichment_status,
                },
            )
            _add_edge(edges, alert_node_id, threat_node_id, "enriched_by_threat_intel")

    alert_ids = {alert.id for alert in alerts}
    for incident in incidents:
        if incident.alert_id and incident.alert_id not in alert_ids:
            continue
        if severity and (incident.severity or "").lower() != severity.lower():
            continue

        incident_node_id = f"incident:{incident.id}"
        _merge_node(
            nodes,
            incident_node_id,
            label=incident.title or f"Incident {incident.id}",
            node_type="incident",
            severity=incident.severity,
            risk_score=SEVERITY_SCORE.get(incident.severity, 35),
            metadata={
                "id": incident.id,
                "status": incident.status,
                "alert_id": incident.alert_id,
                "summary": incident.summary,
            },
        )
        if incident.alert_id:
            _add_edge(edges, f"alert:{incident.alert_id}", incident_node_id, "escalated_to_incident")

    _prune_orphan_event_edges(nodes, edges, event_ids)
    node_values = sorted(nodes.values(), key=lambda node: (node["type"], node["label"]))[:limit]
    allowed_node_ids = {node["id"] for node in node_values}
    edge_values = [
        edge for edge in edges.values() if edge["source"] in allowed_node_ids and edge["target"] in allowed_node_ids
    ]

    return {
        "nodes": node_values,
        "edges": edge_values,
        "summary": {
            "nodes": len(node_values),
            "edges": len(edge_values),
            "high_risk_nodes": sum(
                1
                for node in node_values
                if node.get("risk_score", 0) >= 70 or node.get("severity") in {"high", "critical"}
            ),
        },
    }


def _query_events(
    db: Session,
    source_ip: str | None,
    severity: str | None,
    limit: int,
) -> list[models.SecurityEvent]:
    query = db.query(models.SecurityEvent).order_by(models.SecurityEvent.id.desc())
    if source_ip:
        query = query.filter(models.SecurityEvent.source_ip == source_ip)
    if severity:
        query = query.filter(models.SecurityEvent.severity == severity)
    return query.limit(limit).all()


def _query_alerts(
    db: Session,
    source_ip: str | None,
    severity: str | None,
    limit: int,
) -> list[models.Alert]:
    query = db.query(models.Alert).order_by(models.Alert.id.desc())
    if severity:
        query = query.filter(models.Alert.severity == severity)
    alerts = query.limit(limit).all()
    if not source_ip:
        return alerts
    return [alert for alert in alerts if get_alert_source_ip(db, alert) == source_ip]


def _merge_node(
    nodes: dict[str, dict[str, Any]],
    node_id: str,
    *,
    label: str | None,
    node_type: str,
    severity: str | None,
    risk_score: int,
    metadata: dict[str, Any],
) -> None:
    current = nodes.get(node_id)
    normalized_severity = severity or "info"
    if current:
        current["risk_score"] = max(current.get("risk_score", 0), risk_score)
        if SEVERITY_RANK.get(normalized_severity, 0) > SEVERITY_RANK.get(current.get("severity"), 0):
            current["severity"] = normalized_severity
        current["metadata"].update({key: value for key, value in metadata.items() if value is not None})
        return

    nodes[node_id] = {
        "id": node_id,
        "label": label or node_id,
        "type": node_type,
        "risk_score": risk_score,
        "severity": normalized_severity,
        "metadata": {key: value for key, value in metadata.items() if value is not None},
    }


def _add_edge(edges: dict[str, dict[str, str]], source: str, target: str, relationship: str) -> None:
    edge_id = f"edge:{source}-{target}-{relationship}"
    edges[edge_id] = {
        "id": edge_id,
        "source": source,
        "target": target,
        "relationship": relationship,
    }


def _event_assets(
    event: models.SecurityEvent,
    asset_by_id: dict[int, models.Asset],
    asset_by_ip: dict[str, models.Asset],
) -> list[models.Asset]:
    candidates = [
        asset_by_id.get(event.asset_id) if event.asset_id else None,
        asset_by_ip.get(event.destination_ip),
        asset_by_ip.get(event.source_ip),
    ]
    return list({asset.id: asset for asset in candidates if asset}.values())


def _prune_orphan_event_edges(
    nodes: dict[str, dict[str, Any]],
    edges: dict[str, dict[str, str]],
    event_ids: set[int],
) -> None:
    for event_id in event_ids:
        node_id = f"event:{event_id}"
        if node_id not in nodes:
            _merge_node(
                nodes,
                node_id,
                label=f"Event {event_id}",
                node_type="event",
                severity="info",
                risk_score=0,
                metadata={"id": event_id},
            )
