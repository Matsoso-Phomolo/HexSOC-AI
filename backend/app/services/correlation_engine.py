"""Correlation engine for building SOC attack-chain summaries."""

from collections import defaultdict
from dataclasses import asdict, dataclass
from typing import Any

from sqlalchemy.orm import Session

from app.db import models
from app.services.activity_service import add_activity
from app.services.threat_intel_service import get_alert_source_ip


@dataclass
class CorrelationResult:
    """Attack-chain summary returned to analysts."""

    source_ip: str
    related_events: list[int]
    related_alerts: list[int]
    affected_assets: list[str]
    risk_score: int
    attack_stage: str
    recommended_action: str


def run_correlation(db: Session) -> dict[str, Any]:
    """Correlate events, alerts, assets, and incidents into attack chains."""
    events = db.query(models.SecurityEvent).filter(models.SecurityEvent.source_ip.isnot(None)).all()
    alerts = db.query(models.Alert).all()
    assets = db.query(models.Asset).all()
    incidents = db.query(models.Incident).all()

    events_by_ip: dict[str, list[models.SecurityEvent]] = defaultdict(list)
    alerts_by_ip: dict[str, list[models.Alert]] = defaultdict(list)

    for event in events:
        if event.source_ip:
            events_by_ip[event.source_ip].append(event)

    for alert in alerts:
        source_ip = get_alert_source_ip(db, alert)
        if source_ip:
            alerts_by_ip[source_ip].append(alert)

    source_ips = sorted(set(events_by_ip) | set(alerts_by_ip))
    chains = [
        _build_chain(source_ip, events_by_ip[source_ip], alerts_by_ip[source_ip], assets, incidents)
        for source_ip in source_ips
    ]
    chains = [chain for chain in chains if chain.related_events or chain.related_alerts]
    chains.sort(key=lambda chain: chain.risk_score, reverse=True)

    activity = add_activity(
        db,
        action="correlation_run",
        entity_type="correlation_engine",
        entity_id=None,
        message=f"Correlation engine produced {len(chains)} attack-chain candidates.",
        severity="info",
    )
    db.commit()
    db.refresh(activity)

    return {
        "chains": [asdict(chain) for chain in chains],
        "chains_found": len(chains),
        "source_ips_checked": len(source_ips),
        "activity": activity,
    }


def _build_chain(
    source_ip: str,
    events: list[models.SecurityEvent],
    alerts: list[models.Alert],
    assets: list[models.Asset],
    incidents: list[models.Incident],
) -> CorrelationResult:
    event_types = {(event.event_type or "").lower() for event in events}
    raw_messages = " ".join(event.raw_message or "" for event in events).lower()
    related_alert_ids = {alert.id for alert in alerts}
    linked_incidents = [incident for incident in incidents if incident.alert_id in related_alert_ids]
    affected_assets = _affected_assets(events, assets)
    attack_stage = _attack_stage(event_types, raw_messages, alerts, linked_incidents)
    risk_score = _risk_score(events, alerts, linked_incidents, attack_stage)

    return CorrelationResult(
        source_ip=source_ip,
        related_events=[event.id for event in events],
        related_alerts=sorted(related_alert_ids),
        affected_assets=affected_assets,
        risk_score=risk_score,
        attack_stage=attack_stage,
        recommended_action=_recommended_action(attack_stage, risk_score),
    )


def _affected_assets(events: list[models.SecurityEvent], assets: list[models.Asset]) -> list[str]:
    asset_by_id = {asset.id: asset for asset in assets}
    asset_by_ip = {asset.ip_address: asset for asset in assets if asset.ip_address}
    affected: dict[str, str] = {}

    for event in events:
        candidates = [
            asset_by_id.get(event.asset_id) if event.asset_id else None,
            asset_by_ip.get(event.destination_ip),
            asset_by_ip.get(event.source_ip),
        ]
        for asset in candidates:
            if asset:
                affected[asset.hostname] = asset.ip_address or "unknown-ip"

    return [f"{hostname} ({ip_address})" for hostname, ip_address in sorted(affected.items())]


def _attack_stage(
    event_types: set[str],
    raw_messages: str,
    alerts: list[models.Alert],
    incidents: list[models.Incident],
) -> str:
    has_failed_login = any("failed_login" in event_type for event_type in event_types)
    has_admin_login = any(
        event_type in {"admin_login", "login_success", "unusual_login"} for event_type in event_types
    )
    has_malware = any("malware" in event_type for event_type in event_types) or "malware" in raw_messages
    has_incident = bool(incidents)
    has_alert = bool(alerts)

    if has_failed_login and has_admin_login and has_malware and has_incident:
        return "incident_escalation"
    if has_failed_login and has_admin_login and has_malware:
        return "malware_execution"
    if has_failed_login and has_admin_login:
        return "credential_access_escalation"
    if has_malware:
        return "malware_indicator"
    if has_failed_login and len(alerts) > 0:
        return "brute_force_detected"
    if has_alert:
        return "alert_correlation"
    return "recon_or_noise"


def _risk_score(
    events: list[models.SecurityEvent],
    alerts: list[models.Alert],
    incidents: list[models.Incident],
    attack_stage: str,
) -> int:
    stage_scores = {
        "incident_escalation": 95,
        "malware_execution": 88,
        "credential_access_escalation": 78,
        "malware_indicator": 82,
        "brute_force_detected": 70,
        "alert_correlation": 55,
        "recon_or_noise": 25,
    }
    severity_scores = {"low": 10, "medium": 25, "high": 45, "critical": 60}
    alert_score = max((alert.threat_score or 0 for alert in alerts), default=0)
    severity_score = max(
        [severity_scores.get((alert.severity or "").lower(), 0) for alert in alerts]
        + [severity_scores.get((event.severity or "").lower(), 0) for event in events],
        default=0,
    )
    repetition_bonus = 15 if len(events) >= 5 else 0
    incident_bonus = 10 if incidents else 0

    return min(
        max(stage_scores.get(attack_stage, 25), alert_score, severity_score)
        + repetition_bonus
        + incident_bonus,
        100,
    )


def _recommended_action(attack_stage: str, risk_score: int) -> str:
    if attack_stage in {"incident_escalation", "malware_execution"} or risk_score >= 90:
        return "Escalate to incident response, isolate affected assets, and preserve forensic evidence."
    if attack_stage == "brute_force_detected":
        return "Block source IP, tune authentication controls, and monitor for successful login."
    if attack_stage == "malware_indicator":
        return "Run endpoint containment checks and validate malware quarantine status."
    if attack_stage == "credential_access_escalation" or risk_score >= 75:
        return "Disable or challenge affected credentials and review privileged account activity."
    if attack_stage == "alert_correlation":
        return "Assign analyst review and validate related events before escalation."
    return "Monitor source IP and enrich with additional telemetry if activity continues."
