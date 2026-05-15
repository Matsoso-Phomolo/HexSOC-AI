"""Bounded attack-chain reconstruction from stored SOC telemetry."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any

from sqlalchemy.orm import Session

from app.db import models
from app.services.attack_timeline_builder import SEVERITY_RANK, build_timeline_steps, summarize_timeline

DEFAULT_LIMIT = 50
MAX_LIMIT = 200
MAX_EVENTS_SCAN = 1000
MAX_ALERTS_SCAN = 500
MAX_LINKS_SCAN = 1000


def build_attack_chains(db: Session, *, limit: int = DEFAULT_LIMIT) -> list[dict[str, Any]]:
    """Compute bounded multi-stage attack-chain candidates."""
    safe_limit = _safe_limit(limit)
    events = (
        db.query(models.SecurityEvent)
        .order_by(models.SecurityEvent.created_at.desc(), models.SecurityEvent.id.desc())
        .limit(min(MAX_EVENTS_SCAN, safe_limit * 20))
        .all()
    )
    alerts = (
        db.query(models.Alert)
        .order_by(models.Alert.created_at.desc(), models.Alert.id.desc())
        .limit(min(MAX_ALERTS_SCAN, safe_limit * 10))
        .all()
    )
    assets = db.query(models.Asset).order_by(models.Asset.id.desc()).limit(500).all()
    links = (
        db.query(models.ThreatIOCLink)
        .order_by(models.ThreatIOCLink.created_at.desc(), models.ThreatIOCLink.id.desc())
        .limit(MAX_LINKS_SCAN)
        .all()
    )

    alert_by_event = defaultdict(list)
    for alert in alerts:
        if alert.event_id:
            alert_by_event[alert.event_id].append(alert)

    ioc_counts = _ioc_link_counts(links)
    asset_by_id = {asset.id: asset for asset in assets}
    asset_by_ip = {asset.ip_address: asset for asset in assets if asset.ip_address}
    groups = _group_events(events)

    chains: list[dict[str, Any]] = []
    for group_key, group_events in groups.items():
        if len(group_events) < 2 and not _has_high_value_signal(group_events, alert_by_event, ioc_counts):
            continue
        group_alerts = _related_alerts(group_events, alerts, alert_by_event, group_key)
        chain = _build_chain(group_key, group_events, group_alerts, asset_by_id, asset_by_ip, ioc_counts)
        if chain:
            chains.append(chain)

    chains.sort(key=lambda item: (item["risk_score"], item["timeline"]["last_seen"] or ""), reverse=True)
    return chains[:safe_limit]


def get_attack_chain(db: Session, chain_id: str) -> dict[str, Any] | None:
    """Find one computed attack chain by deterministic ID."""
    for chain in build_attack_chains(db, limit=MAX_LIMIT):
        if chain["chain_id"] == chain_id:
            return chain
    return None


def rebuild_attack_chains(db: Session, *, limit: int = DEFAULT_LIMIT) -> dict[str, Any]:
    """Compute chain summary for explicit analyst-triggered rebuild runs."""
    chains = build_attack_chains(db, limit=limit)
    return {
        "chains_found": len(chains),
        "highest_risk_score": max((chain["risk_score"] for chain in chains), default=0),
        "critical_chains": sum(1 for chain in chains if chain["classification"] == "critical"),
        "high_chains": sum(1 for chain in chains if chain["classification"] == "high"),
        "chains": chains,
    }


def _build_chain(
    group_key: str,
    events: list[Any],
    alerts: list[Any],
    asset_by_id: dict[int, Any],
    asset_by_ip: dict[str, Any],
    ioc_counts: dict[tuple[str, int], int],
) -> dict[str, Any] | None:
    steps = build_timeline_steps(events, alerts)
    if not steps:
        return None

    timeline = summarize_timeline(steps)
    source_ips = _ordered_unique(event.source_ip for event in events if event.source_ip)
    destination_ips = _ordered_unique(event.destination_ip for event in events if event.destination_ip)
    usernames = _ordered_unique(event.username for event in events if event.username)
    asset_ids = _ordered_unique(event.asset_id for event in events if event.asset_id)
    assets = _asset_summaries(events, asset_ids, asset_by_id, asset_by_ip)
    techniques = _ordered_unique(
        value
        for value in [*(event.mitre_technique_id for event in events), *(alert.mitre_technique_id for alert in alerts)]
        if value
    )
    tactics = _ordered_unique(
        value for value in [*(event.mitre_tactic for event in events), *(alert.mitre_tactic for alert in alerts)] if value
    )
    related_ioc_count = sum(ioc_counts.get(("event", event.id), 0) for event in events) + sum(
        ioc_counts.get(("alert", alert.id), 0) for alert in alerts
    )
    risk_score = _score_chain(steps, alerts, related_ioc_count, len(tactics), len(techniques))
    classification = _classify(risk_score)
    chain_id = _chain_id(group_key, events, alerts)
    title = _chain_title(group_key, timeline["stages"], risk_score)

    return {
        "chain_id": chain_id,
        "title": title,
        "primary_group": group_key,
        "primary_source_ip": source_ips[0] if source_ips else None,
        "related_source_ips": source_ips[:20],
        "destination_ips": destination_ips[:20],
        "usernames": usernames[:20],
        "affected_assets": assets[:20],
        "related_events": {"count": len(events), "ids": [event.id for event in events[:50]]},
        "related_alerts": {"count": len(alerts), "ids": [alert.id for alert in alerts[:50]]},
        "related_iocs": {"count": related_ioc_count},
        "stages": timeline["stages"],
        "mitre_tactics": tactics[:20],
        "mitre_techniques": techniques[:20],
        "timeline": timeline,
        "risk_score": risk_score,
        "confidence": _confidence(steps, alerts, related_ioc_count),
        "severity": timeline["highest_severity"],
        "classification": classification,
        "recommended_action": _recommended_action(classification, timeline["stages"]),
        "timeline_steps": steps[:100],
    }


def _group_events(events: list[Any]) -> dict[str, list[Any]]:
    groups: dict[str, list[Any]] = defaultdict(list)
    for event in events:
        key = _group_key(event)
        if key:
            groups[key].append(event)
    return groups


def _group_key(event: Any) -> str | None:
    if event.source_ip:
        return f"source_ip:{event.source_ip}"
    payload = event.raw_payload if isinstance(event.raw_payload, dict) else {}
    hostname = payload.get("hostname") or payload.get("computer") or payload.get("host_name")
    if hostname:
        return f"hostname:{hostname}"
    if event.username:
        return f"username:{event.username}"
    if event.asset_id:
        return f"asset:{event.asset_id}"
    if event.mitre_technique_id:
        return f"mitre:{event.mitre_technique_id}"
    return None


def _related_alerts(group_events: list[Any], alerts: list[Any], alert_by_event: dict[int, list[Any]], group_key: str) -> list[Any]:
    related: dict[int, Any] = {}
    event_ids = {event.id for event in group_events}
    for event in group_events:
        for alert in alert_by_event.get(event.id, []):
            related[alert.id] = alert
    if group_key.startswith("source_ip:"):
        source_ip = group_key.split(":", 1)[1]
        for alert in alerts:
            text = f"{alert.title or ''} {alert.description or ''}"
            if source_ip and source_ip in text:
                related[alert.id] = alert
    for alert in alerts:
        if alert.event_id in event_ids:
            related[alert.id] = alert
    return sorted(related.values(), key=lambda alert: (alert.created_at, alert.id))


def _ioc_link_counts(links: list[Any]) -> dict[tuple[str, int], int]:
    counts: dict[tuple[str, int], int] = defaultdict(int)
    for link in links:
        counts[(link.entity_type, link.entity_id)] += 1
    return counts


def _has_high_value_signal(group_events: list[Any], alert_by_event: dict[int, list[Any]], ioc_counts: dict[tuple[str, int], int]) -> bool:
    for event in group_events:
        if SEVERITY_RANK.get(event.severity, 0) >= SEVERITY_RANK["high"]:
            return True
        if alert_by_event.get(event.id):
            return True
        if ioc_counts.get(("event", event.id), 0):
            return True
    return False


def _score_chain(
    steps: list[dict[str, Any]],
    alerts: list[Any],
    related_ioc_count: int,
    tactic_count: int,
    technique_count: int,
) -> int:
    stages = {step.get("attack_stage") for step in steps if step.get("attack_stage")}
    score = min(len(stages) * 8, 35)
    max_severity = max((SEVERITY_RANK.get(step.get("severity") or "info", 0) for step in steps), default=0)
    score += max_severity * 8
    score += min(tactic_count * 5, 20)
    score += min(technique_count * 3, 15)
    score += min(related_ioc_count * 7, 20)
    if any((alert.confidence_score or 0) >= 80 for alert in alerts):
        score += 10
    if "Credential Access" in stages:
        score += 10
    if "Lateral Movement" in stages:
        score += 12
    if "Command and Control" in stages:
        score += 12
    if "Impact" in stages:
        score += 15
    return min(score, 100)


def _confidence(steps: list[dict[str, Any]], alerts: list[Any], related_ioc_count: int) -> int:
    base = 45
    base += min(len({step.get("attack_stage") for step in steps if step.get("attack_stage")}) * 7, 25)
    base += min(len(alerts) * 5, 15)
    base += min(related_ioc_count * 5, 15)
    alert_confidence = max((alert.confidence_score or 0 for alert in alerts), default=0)
    if alert_confidence:
        base = max(base, alert_confidence)
    return min(base, 100)


def _classify(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "suspicious"
    return "low"


def _recommended_action(classification: str, stages: list[str]) -> str:
    if classification == "critical":
        return "Escalate as active intrusion, contain affected assets, and validate credential exposure immediately."
    if "Lateral Movement" in stages or "Credential Access" in stages:
        return "Prioritize identity review, isolate implicated hosts, and hunt for adjacent asset activity."
    if classification == "high":
        return "Open or update an incident case and collect endpoint, authentication, and network evidence."
    if classification == "suspicious":
        return "Triage related telemetry and monitor for repeated activity or additional MITRE stage progression."
    return "Monitor and enrich if the same indicators recur."


def _chain_id(group_key: str, events: list[Any], alerts: list[Any]) -> str:
    material = "|".join([group_key, *[f"e{event.id}" for event in events[:50]], *[f"a{alert.id}" for alert in alerts[:50]]])
    return f"chain:{hashlib.sha1(material.encode('utf-8')).hexdigest()[:16]}"


def _chain_title(group_key: str, stages: list[str], risk_score: int) -> str:
    label = group_key.replace("source_ip:", "Source IP ").replace("hostname:", "Host ").replace("username:", "User ")
    if stages:
        return f"{label} attack chain: {' -> '.join(stages[:3])} ({risk_score})"
    return f"{label} attack chain ({risk_score})"


def _asset_summaries(events: list[Any], asset_ids: list[int], asset_by_id: dict[int, Any], asset_by_ip: dict[str, Any]) -> list[dict[str, Any]]:
    assets: dict[int, Any] = {}
    for asset_id in asset_ids:
        asset = asset_by_id.get(asset_id)
        if asset:
            assets[asset.id] = asset
    for event in events:
        for ip in [event.source_ip, event.destination_ip]:
            asset = asset_by_ip.get(ip)
            if asset:
                assets[asset.id] = asset
    return [
        {
            "id": asset.id,
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "role": asset.role,
            "criticality": asset.criticality,
        }
        for asset in assets.values()
    ]


def _ordered_unique(values: Any) -> list[Any]:
    seen: set[Any] = set()
    result: list[Any] = []
    for value in values:
        if value is not None and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _safe_limit(limit: int) -> int:
    return max(1, min(limit or DEFAULT_LIMIT, MAX_LIMIT))
