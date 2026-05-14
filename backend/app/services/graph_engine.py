"""Investigation graph builder for SOC relationship analysis."""

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.db import models
from app.services.threat_intel_service import get_alert_source_ip


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_SCORE = {"info": 0, "low": 15, "medium": 35, "high": 70, "critical": 90}
GRAPH_EVENT_SCAN_LIMIT = 900
GRAPH_ALERT_SCAN_LIMIT = 450
GRAPH_ASSET_SCAN_LIMIT = 500
GRAPH_INCIDENT_SCAN_LIMIT = 200
RELATIONSHIP_WEIGHTS = {
    "targets_asset": 90,
    "raised_alert": 85,
    "mapped_to": 80,
    "triggered_alert_cluster": 78,
    "escalated_to_incident": 95,
    "generated_event_cluster": 65,
    "affects_asset": 72,
    "associated_with": 45,
    "connected_to": 40,
    "executed_in": 50,
    "enriched_by_threat_intel": 70,
    "correlated_with": 60,
}


def build_investigation_graph(
    db: Session,
    source_ip: str | None = None,
    severity: str | None = None,
    node_type: str | None = None,
    mitre_tactic: str | None = None,
    hostname: str | None = None,
    time_window: str | None = None,
    aggregate: bool = True,
    limit: int = 150,
) -> dict[str, Any]:
    """Build source IP, event, alert, incident, asset, and threat intel graph data."""
    limit = max(1, min(limit, 500))
    if aggregate:
        return build_aggregated_investigation_graph(
            db,
            source_ip=source_ip,
            severity=severity,
            node_type=node_type,
            mitre_tactic=mitre_tactic,
            hostname=hostname,
            time_window=time_window,
            limit=limit,
        )

    events = _query_events(db, source_ip, severity, limit, mitre_tactic=mitre_tactic, hostname=hostname, time_window=time_window)
    alerts = _query_alerts(db, source_ip, severity, limit, mitre_tactic=mitre_tactic, time_window=time_window)
    assets = db.query(models.Asset).order_by(models.Asset.id.desc()).limit(GRAPH_ASSET_SCAN_LIMIT).all()
    incidents = db.query(models.Incident).order_by(models.Incident.id.desc()).limit(GRAPH_INCIDENT_SCAN_LIMIT).all()

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
                    "mitre_tactic": event.mitre_tactic,
                    "mitre_technique": event.mitre_technique,
                    "mitre_technique_id": event.mitre_technique_id,
                    "mitre_confidence": event.mitre_confidence,
                    "mitre_reason": event.mitre_reason,
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
                "mitre_tactic": alert.mitre_tactic,
                "mitre_technique": alert.mitre_technique,
                "mitre_technique_id": alert.mitre_technique_id,
                "mitre_confidence": alert.confidence_score,
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
    node_values = _filter_nodes_by_type(nodes.values(), node_type)
    node_values = sorted(node_values, key=lambda node: (node["type"], node["label"]))[:limit]
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


def build_aggregated_investigation_graph(
    db: Session,
    source_ip: str | None = None,
    severity: str | None = None,
    node_type: str | None = None,
    mitre_tactic: str | None = None,
    hostname: str | None = None,
    time_window: str | None = None,
    limit: int = 150,
) -> dict[str, Any]:
    """Build an enterprise investigation graph with server-side aggregation."""
    scan_event_limit = min(max(limit * 8, 300), GRAPH_EVENT_SCAN_LIMIT)
    scan_alert_limit = min(max(limit * 4, 200), GRAPH_ALERT_SCAN_LIMIT)
    events = _query_events(db, source_ip, severity, scan_event_limit, mitre_tactic=mitre_tactic, hostname=hostname, time_window=time_window)
    alerts = _query_alerts(db, source_ip, severity, scan_alert_limit, mitre_tactic=mitre_tactic, time_window=time_window)
    assets = db.query(models.Asset).order_by(models.Asset.id.desc()).limit(GRAPH_ASSET_SCAN_LIMIT).all()
    incidents = db.query(models.Incident).order_by(models.Incident.id.desc()).limit(GRAPH_INCIDENT_SCAN_LIMIT).all()

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, str]] = {}
    asset_by_id = {asset.id: asset for asset in assets}
    asset_by_ip = {asset.ip_address: asset for asset in assets if asset.ip_address}
    event_by_id = {event.id: event for event in events}
    event_cluster_by_event_id: dict[int, str] = {}

    top_source_ips: Counter[str] = Counter()
    top_techniques: Counter[str] = Counter()
    asset_connections: Counter[str] = Counter()
    aggressive_aggregation = len(events) + len(alerts) > 100

    event_clusters: dict[tuple[str, str, str | None], list[models.SecurityEvent]] = defaultdict(list)
    for event in events:
        source_key = event.source_ip or "unknown"
        event_family = _graph_cluster_family(event.event_type or "windows_event")
        technique_key = None if aggressive_aggregation else event.mitre_technique_id
        event_clusters[(source_key, event_family, technique_key)].append(event)
        if event.source_ip:
            top_source_ips[event.source_ip] += 1
        if event.mitre_technique_id:
            top_techniques[f"{event.mitre_technique_id} {event.mitre_technique or ''}".strip()] += 1

    for (source_key, event_type, technique_id), cluster_events in event_clusters.items():
        severity_value = _max_severity([event.severity for event in cluster_events])
        risk_score = max([event.risk_score or SEVERITY_SCORE.get(event.severity, 20) for event in cluster_events] or [0])
        event_cluster_id = f"event_cluster:{source_key}:{event_type}:{technique_id or 'none'}"
        for event in cluster_events:
            event_cluster_by_event_id[event.id] = event_cluster_id
        _merge_node(
            nodes,
            event_cluster_id,
            label=f"{_humanize_event_type(event_type)} ({len(cluster_events)})",
            node_type="event_cluster",
            severity=severity_value,
            risk_score=risk_score,
            metadata={
                "event_type": event_type,
                "count": len(cluster_events),
                "source_ip": source_key if source_key != "unknown" else None,
                "mitre_technique_id": technique_id,
                "sample_event_ids": [event.id for event in cluster_events[:10]],
                "first_seen": min(event.created_at for event in cluster_events if event.created_at).isoformat()
                if any(event.created_at for event in cluster_events)
                else None,
                "last_seen": max(event.created_at for event in cluster_events if event.created_at).isoformat()
                if any(event.created_at for event in cluster_events)
                else None,
            },
        )

        if source_key != "unknown":
            ip_node_id = f"source_ip:{source_key}"
            _merge_node(nodes, ip_node_id, label=source_key, node_type="source_ip", severity=severity_value, risk_score=risk_score, metadata={"source_ip": source_key, "event_count": len(cluster_events)})
            _add_edge(edges, ip_node_id, event_cluster_id, "generated_event_cluster")

        for event in cluster_events:
            if event.destination_ip:
                dst_node_id = f"destination_ip:{event.destination_ip}"
                _merge_node(nodes, dst_node_id, label=event.destination_ip, node_type="destination_ip", severity=event.severity, risk_score=SEVERITY_SCORE.get(event.severity, 20), metadata={"destination_ip": event.destination_ip})
                _add_edge(edges, event_cluster_id, dst_node_id, "connected_to")
            if event.username:
                user_node_id = f"user:{event.username}"
                _merge_node(nodes, user_node_id, label=event.username, node_type="user", severity=event.severity, risk_score=SEVERITY_SCORE.get(event.severity, 20), metadata={"username": event.username})
                _add_edge(edges, user_node_id, event_cluster_id, "associated_with")
            process_name = _event_process_name(event)
            if process_name:
                process_node_id = f"process:{process_name.lower()}"
                _merge_node(nodes, process_node_id, label=process_name, node_type="process", severity=event.severity, risk_score=SEVERITY_SCORE.get(event.severity, 20), metadata={"process": process_name})
                _add_edge(edges, process_node_id, event_cluster_id, "executed_in")
            if event.mitre_technique_id:
                technique_node_id = f"mitre:{event.mitre_technique_id}"
                _merge_node(nodes, technique_node_id, label=event.mitre_technique_id, node_type="mitre_technique", severity=event.severity, risk_score=SEVERITY_SCORE.get(event.severity, 20), metadata={"tactic": event.mitre_tactic, "technique": event.mitre_technique, "technique_id": event.mitre_technique_id, "reason": event.mitre_reason})
                _add_edge(edges, event_cluster_id, technique_node_id, "mapped_to")

            for asset in _event_assets(event, asset_by_id, asset_by_ip):
                asset_node_id = f"asset:{asset.id}"
                asset_connections[asset.hostname] += 1
                _merge_node(nodes, asset_node_id, label=asset.hostname, node_type="asset", severity=asset.criticality or event.severity, risk_score=max(SEVERITY_SCORE.get(asset.criticality or "medium", 35), SEVERITY_SCORE.get(event.severity, 20)), metadata={"id": asset.id, "hostname": asset.hostname, "ip_address": asset.ip_address, "role": asset.role, "connection_count": asset_connections[asset.hostname]})
                if source_key != "unknown":
                    _add_edge(edges, f"source_ip:{source_key}", asset_node_id, "targets_asset")
                _add_edge(edges, event_cluster_id, asset_node_id, "affects_asset")

    alert_clusters: dict[tuple[str, str, str], list[models.Alert]] = defaultdict(list)
    for alert in alerts:
        resolved_source_ip = get_alert_source_ip(db, alert) or "unknown"
        cluster_key = _graph_cluster_family(alert.detection_rule or _alert_family(alert.title))
        severity_key = "cluster" if aggressive_aggregation else alert.severity or "medium"
        alert_clusters[(resolved_source_ip, cluster_key, severity_key)].append(alert)

    alert_cluster_members: dict[str, set[int]] = {}
    for (source_key, cluster_key, severity_key), cluster_alerts in alert_clusters.items():
        alert_severity = _max_severity([alert.severity for alert in cluster_alerts]) if severity_key == "cluster" else severity_key
        risk_score = max([alert.threat_score or SEVERITY_SCORE.get(alert.severity, 35) for alert in cluster_alerts] or [0])
        alert_cluster_id = f"alert_cluster:{source_key}:{cluster_key}:{alert_severity}"
        alert_cluster_members[alert_cluster_id] = {alert.id for alert in cluster_alerts}
        _merge_node(
            nodes,
            alert_cluster_id,
            label=f"{_humanize_event_type(cluster_key)} ({len(cluster_alerts)})",
            node_type="alert_cluster",
            severity=alert_severity,
            risk_score=risk_score,
            metadata={
                "alert_family": cluster_key,
                "count": len(cluster_alerts),
                "source_ip": source_key if source_key != "unknown" else None,
                "sample_alert_ids": [alert.id for alert in cluster_alerts[:10]],
                "first_seen": min(alert.created_at for alert in cluster_alerts if alert.created_at).isoformat()
                if any(alert.created_at for alert in cluster_alerts)
                else None,
                "last_seen": max(alert.created_at for alert in cluster_alerts if alert.created_at).isoformat()
                if any(alert.created_at for alert in cluster_alerts)
                else None,
            },
        )
        if source_key != "unknown":
            ip_node_id = f"source_ip:{source_key}"
            _merge_node(nodes, ip_node_id, label=source_key, node_type="source_ip", severity=alert_severity, risk_score=risk_score, metadata={"source_ip": source_key})
            _add_edge(edges, ip_node_id, alert_cluster_id, "triggered_alert_cluster")
        for alert in cluster_alerts:
            if alert.event_id and alert.event_id in event_by_id:
                linked_event = event_by_id[alert.event_id]
                event_cluster_id = event_cluster_by_event_id.get(alert.event_id) or f"event_cluster:{linked_event.source_ip or 'unknown'}:{linked_event.event_type or 'windows_event'}:{linked_event.mitre_technique_id or 'none'}"
                if event_cluster_id in nodes:
                    _add_edge(edges, event_cluster_id, alert_cluster_id, "triggered_alert_cluster")
                for asset in _event_assets(linked_event, asset_by_id, asset_by_ip):
                    asset_node_id = f"asset:{asset.id}"
                    if asset_node_id in nodes:
                        _add_edge(edges, asset_node_id, alert_cluster_id, "raised_alert")
            if alert.mitre_technique_id:
                technique_node_id = f"mitre:{alert.mitre_technique_id}"
                _merge_node(nodes, technique_node_id, label=alert.mitre_technique_id, node_type="mitre_technique", severity=alert.severity, risk_score=SEVERITY_SCORE.get(alert.severity, 35), metadata={"tactic": alert.mitre_tactic, "technique": alert.mitre_technique, "technique_id": alert.mitre_technique_id})
                _add_edge(edges, alert_cluster_id, technique_node_id, "mapped_to")

    for incident in incidents:
        if severity and (incident.severity or "").lower() != severity.lower():
            continue
        incident_node_id = f"incident:{incident.id}"
        _merge_node(nodes, incident_node_id, label=incident.title or f"Incident {incident.id}", node_type="incident", severity=incident.severity, risk_score=SEVERITY_SCORE.get(incident.severity, 35), metadata={"id": incident.id, "status": incident.status, "alert_id": incident.alert_id, "summary": incident.summary})
        if incident.alert_id:
            for alert_cluster_id, member_ids in alert_cluster_members.items():
                if incident.alert_id in member_ids:
                    _add_edge(edges, alert_cluster_id, incident_node_id, "escalated_to_incident")

    degree = Counter()
    relationship_weights = Counter()
    for edge in edges.values():
        degree[edge["source"]] += 1
        degree[edge["target"]] += 1
        relationship_weights[edge["relationship"]] += int(edge.get("weight", 1))

    node_values = _filter_nodes_by_type(nodes.values(), node_type)
    effective_limit = min(limit, 100) if len(node_values) > 100 else limit
    node_values = sorted(node_values, key=lambda node: _graph_node_sort_key(node, degree))[:effective_limit]
    allowed_node_ids = {node["id"] for node in node_values}
    edge_values = [edge for edge in edges.values() if edge["source"] in allowed_node_ids and edge["target"] in allowed_node_ids]

    return {
        "nodes": node_values,
        "edges": edge_values,
        "summary": {
            "nodes": len(node_values),
            "edges": len(edge_values),
            "high_risk_nodes": sum(1 for node in node_values if _is_high_risk_node(node)),
            "high_risk_clusters": sum(1 for node in node_values if node["type"] in {"event_cluster", "alert_cluster"} and _is_high_risk_node(node)),
            "top_source_ips": _counter_items(top_source_ips),
            "top_techniques": _counter_items(top_techniques),
            "most_connected_assets": _counter_items(asset_connections),
            "aggregation": "clustered",
            "limit": effective_limit,
            "available_nodes": len(nodes),
            "available_edges": len(edges),
            "aggressive_aggregation": aggressive_aggregation,
            "relationship_weights": _counter_items(relationship_weights),
            "timeline_ready": True,
        },
    }


def _query_events(
    db: Session,
    source_ip: str | None,
    severity: str | None,
    limit: int,
    mitre_tactic: str | None = None,
    hostname: str | None = None,
    time_window: str | None = None,
) -> list[models.SecurityEvent]:
    query = db.query(models.SecurityEvent).order_by(models.SecurityEvent.id.desc())
    if source_ip:
        query = query.filter(models.SecurityEvent.source_ip == source_ip)
    if severity:
        query = query.filter(models.SecurityEvent.severity == severity)
    if mitre_tactic:
        query = query.filter(models.SecurityEvent.mitre_tactic == mitre_tactic)
    cutoff = _time_window_cutoff(time_window)
    if cutoff:
        query = query.filter(models.SecurityEvent.created_at >= cutoff)
    events = query.limit(limit).all()
    if hostname:
        return [event for event in events if _event_hostname(event).lower() == hostname.lower()]
    return events


def _query_alerts(
    db: Session,
    source_ip: str | None,
    severity: str | None,
    limit: int,
    mitre_tactic: str | None = None,
    time_window: str | None = None,
) -> list[models.Alert]:
    query = db.query(models.Alert).order_by(models.Alert.id.desc())
    if severity:
        query = query.filter(models.Alert.severity == severity)
    if mitre_tactic:
        query = query.filter(models.Alert.mitre_tactic == mitre_tactic)
    cutoff = _time_window_cutoff(time_window)
    if cutoff:
        query = query.filter(models.Alert.created_at >= cutoff)
    alerts = query.limit(limit).all()
    if not source_ip:
        return alerts
    return [alert for alert in alerts if get_alert_source_ip(db, alert) == source_ip]


def _time_window_cutoff(time_window: str | None) -> datetime | None:
    if not time_window:
        return None
    now = datetime.now(timezone.utc)
    windows = {
        "1h": timedelta(hours=1),
        "6h": timedelta(hours=6),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }
    delta = windows.get(time_window)
    return now - delta if delta else None


def _filter_nodes_by_type(nodes: Any, node_type: str | None) -> list[dict[str, Any]]:
    values = list(nodes)
    if not node_type:
        return values
    return [node for node in values if node.get("type") == node_type]


def _max_severity(values: list[str | None]) -> str:
    return max([value or "info" for value in values], key=lambda value: SEVERITY_RANK.get(value, 0), default="info")


def _humanize_event_type(value: str | None) -> str:
    label = (value or "event").replace("_", " ").strip().title()
    if label.endswith("S"):
        return label
    return label


def _alert_family(title: str | None) -> str:
    normalized = (title or "alert").lower()
    if "malware" in normalized:
        return "malware_events"
    if "failed" in normalized or "brute" in normalized:
        return "failed_logins"
    if "dns" in normalized:
        return "dns_queries"
    if "process" in normalized:
        return "process_creates"
    return normalized[:60].replace(" ", "_")


def _graph_cluster_family(value: str | None) -> str:
    normalized = (value or "event").lower()
    if "malware" in normalized or "beacon" in normalized or "ransomware" in normalized:
        return "malware_indicator"
    if "failed_login" in normalized or "brute" in normalized:
        return "failed_login"
    if "credential" in normalized or "lsass" in normalized or "mimikatz" in normalized:
        return "credential_access"
    if "lateral" in normalized or "psexec" in normalized or "wmic" in normalized or "winrm" in normalized:
        return "lateral_movement"
    if "dns" in normalized:
        return "dns_query"
    if "process" in normalized:
        return "process_create"
    return normalized.replace(" ", "_")[:60]


def _event_process_name(event: models.SecurityEvent) -> str | None:
    payload = event.raw_payload or {}
    if isinstance(payload, dict):
        fields = payload.get("fields") if isinstance(payload.get("fields"), dict) else payload
        for key in ("Image", "ProcessName", "process", "CommandLine", "ParentImage"):
            value = fields.get(key)
            if value:
                return str(value).split("\\")[-1].split("/")[-1][:80]
    return None


def _event_hostname(event: models.SecurityEvent) -> str:
    payload = event.raw_payload or {}
    if isinstance(payload, dict):
        fields = payload.get("fields") if isinstance(payload.get("fields"), dict) else payload
        for key in ("computer", "Computer", "hostname", "Hostname", "HostName"):
            value = fields.get(key) or payload.get(key)
            if value:
                return str(value)
    return ""


def _is_high_risk_node(node: dict[str, Any]) -> bool:
    return node.get("risk_score", 0) >= 70 or node.get("severity") in {"high", "critical"}


def _counter_items(counter: Counter[str], limit: int = 5) -> list[dict[str, Any]]:
    return [{"label": label, "count": count} for label, count in counter.most_common(limit)]


def _graph_node_sort_key(node: dict[str, Any], degree: Counter[str]) -> tuple[int, int, int, str]:
    type_priority = {
        "source_ip": 100,
        "asset": 95,
        "alert_cluster": 90,
        "mitre_technique": 82,
        "incident": 78,
        "event_cluster": 72,
        "user": 55,
        "process": 50,
        "destination_ip": 45,
    }
    node_degree = degree.get(node["id"], 0)
    risk_score = int(node.get("risk_score", 0))
    priority = type_priority.get(node.get("type"), 0)
    return (-(node_degree * 35 + risk_score + priority), -node_degree, -risk_score, node["label"])


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


def _add_edge(edges: dict[str, dict[str, Any]], source: str, target: str, relationship: str) -> None:
    edge_id = f"edge:{source}-{target}-{relationship}"
    weight = RELATIONSHIP_WEIGHTS.get(relationship, 50)
    edges[edge_id] = {
        "id": edge_id,
        "source": source,
        "target": target,
        "relationship": relationship,
        "weight": weight,
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
