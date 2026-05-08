"""Deterministic AI Analyst Copilot service.

This module is intentionally rule-based for Phase 2D.1. It keeps the response
shape LLM-ready without calling external model providers.
"""

from typing import Any

from app.db import models


def summarize_alert(alert: models.Alert) -> dict[str, Any]:
    """Generate a structured SOC analyst summary for an alert."""
    risk = _risk_assessment(
        severity=alert.severity,
        threat_score=alert.threat_score,
        status=alert.status,
    )
    actions = recommend_response(alert)

    return {
        "summary": _alert_summary(alert),
        "risk_assessment": risk,
        "recommended_actions": actions,
        "mitre_explanation": explain_mitre(alert),
        "investigation_notes": generate_investigation_notes(alert),
        "confidence": _confidence(alert),
    }


def summarize_incident(incident: models.Incident) -> dict[str, Any]:
    """Generate a structured SOC analyst summary for an incident."""
    severity = (incident.severity or "medium").lower()
    status = incident.status or "open"
    title = incident.title or f"Incident {incident.id}"

    return {
        "summary": f"{title} is a {severity} severity incident currently marked {status}.",
        "risk_assessment": _incident_risk_assessment(incident),
        "recommended_actions": _incident_actions(incident),
        "mitre_explanation": "No specific MITRE technique is attached to this incident yet.",
        "investigation_notes": generate_investigation_notes(incident),
        "confidence": 78 if incident.alert_id else 68,
    }


def explain_mitre(alert: models.Alert) -> str:
    """Explain MITRE ATT&CK context attached to an alert."""
    rule = (alert.detection_rule or "").lower()

    if alert.mitre_technique:
        return (
            f"{alert.mitre_technique} is mapped to {alert.mitre_tactic or 'an ATT&CK tactic'}. "
            "Treat this as a hypothesis for analyst validation, not final attribution."
        )
    if "failed_login_spike" in rule:
        return "Likely maps to T1110 Brute Force under Credential Access."
    if "unusual_admin_login" in rule:
        return "Likely maps to T1078 Valid Accounts because privileged credentials may have been used."
    if "malware_indicator" in rule:
        return "Likely maps to execution or user-execution behavior, depending on endpoint evidence."
    return "No MITRE mapping is available yet. Add rule metadata or analyst tagging to improve context."


def recommend_response(alert: models.Alert) -> list[str]:
    """Return severity and rule-aware analyst response actions."""
    rule = (alert.detection_rule or "").lower()
    actions: list[str] = []

    if "failed_login_spike" in rule:
        actions.extend(
            [
                "Review authentication logs for the source IP and affected username.",
                "Force password reset if a user account shows repeated failures followed by success.",
                "Confirm MFA enforcement and lockout policy coverage.",
                "Block or rate-limit the source IP if activity is external.",
            ]
        )
    elif "malware_indicator" in rule:
        actions.extend(
            [
                "Isolate the affected host from the network.",
                "Collect EDR process tree, file hash, and command-line evidence.",
                "Validate quarantine status and scan neighboring assets.",
                "Open or escalate an incident if containment is not confirmed.",
            ]
        )
    elif "unusual_admin_login" in rule:
        actions.extend(
            [
                "Validate whether the privileged login was expected.",
                "Review recent admin account changes and session activity.",
                "Rotate credentials if the login source or timing is suspicious.",
            ]
        )
    else:
        actions.extend(
            [
                "Validate alert evidence and related events.",
                "Check affected assets and user context.",
                "Escalate if additional alerts share the same source IP or account.",
            ]
        )

    if (alert.threat_score or 0) >= 70:
        actions.insert(0, "Treat the source as high-risk because threat intelligence score is elevated.")
    if (alert.severity or "").lower() == "critical":
        actions.insert(0, "Prioritize immediate containment and incident commander notification.")

    return actions


def generate_attack_chain_summary(chain: dict[str, Any]) -> dict[str, Any]:
    """Generate a concise analyst explanation for an attack-chain result."""
    stage = chain.get("attack_stage", "unknown")
    risk_score = int(chain.get("risk_score") or 0)
    source_ip = chain.get("source_ip", "unknown source")
    events = chain.get("related_events", [])
    alerts = chain.get("related_alerts", [])
    assets = chain.get("affected_assets", [])

    return {
        "summary": (
            f"Source {source_ip} is correlated to {len(events)} events and {len(alerts)} alerts "
            f"at attack stage {stage}."
        ),
        "risk_assessment": _chain_risk(stage, risk_score),
        "recommended_actions": _chain_actions(stage, risk_score),
        "mitre_explanation": _chain_mitre(stage),
        "investigation_notes": (
            f"Affected assets: {', '.join(assets) if assets else 'none identified yet'}. "
            "Validate sequence timing, authentication outcomes, and endpoint telemetry."
        ),
        "confidence": min(max(risk_score, 55), 95),
    }


def generate_investigation_notes(alert_or_incident: models.Alert | models.Incident) -> str:
    """Generate compact analyst investigation notes."""
    if isinstance(alert_or_incident, models.Alert):
        alert = alert_or_incident
        notes = [
            f"Alert status: {alert.status}.",
            f"Severity: {alert.severity}.",
            f"Detection rule: {alert.detection_rule or 'manual or unknown'}.",
        ]
        if alert.threat_score is not None:
            notes.append(
                f"Threat intel: {alert.threat_source or 'unknown provider'} scored this context {alert.threat_score}."
            )
        if alert.geo_country or alert.isp:
            notes.append(f"Geo/ISP context: {alert.geo_country or 'unknown country'} / {alert.isp or 'unknown ISP'}.")
        return " ".join(notes)

    incident = alert_or_incident
    return (
        f"Incident status: {incident.status}. Severity: {incident.severity}. "
        f"Linked alert: {incident.alert_id or 'none'}. "
        "Review case notes, containment status, and any linked alert evidence."
    )


def _alert_summary(alert: models.Alert) -> str:
    rule = alert.detection_rule or "manual alert"
    title = alert.title or f"Alert {alert.id}"
    return f"{title} is a {alert.severity} severity alert generated from {rule}."


def _risk_assessment(severity: str | None, threat_score: int | None, status: str | None) -> str:
    normalized = (severity or "medium").lower()
    score = threat_score or 0
    if normalized == "critical" or score >= 85:
        return "Critical risk. Immediate containment and escalation are recommended."
    if normalized == "high" or score >= 70:
        return "High risk. Analyst validation should happen quickly, with containment ready."
    if normalized == "medium" or score >= 40:
        return "Moderate risk. Correlate with user, asset, and network telemetry."
    return f"Lower immediate risk while status remains {status or 'unknown'}, but monitor for recurrence."


def _incident_risk_assessment(incident: models.Incident) -> str:
    severity = (incident.severity or "medium").lower()
    if severity == "critical":
        return "Critical incident risk. Confirm containment, scope, and evidence preservation."
    if severity == "high":
        return "High incident risk. Prioritize triage, ownership, and response timeline."
    return "Moderate incident risk. Continue validation and track response milestones."


def _incident_actions(incident: models.Incident) -> list[str]:
    actions = [
        "Confirm incident owner and current containment status.",
        "Review linked alert evidence and related graph relationships.",
        "Document timeline, affected assets, and response decisions.",
    ]
    if (incident.severity or "").lower() in {"high", "critical"}:
        actions.insert(0, "Escalate to the response lead and validate business impact.")
    return actions


def _confidence(alert: models.Alert) -> int:
    confidence = 62
    if alert.detection_rule:
        confidence += 12
    if alert.mitre_technique:
        confidence += 8
    if alert.threat_score is not None:
        confidence += 8
    if (alert.severity or "").lower() in {"high", "critical"}:
        confidence += 6
    return min(confidence, 96)


def _chain_risk(stage: str, risk_score: int) -> str:
    if risk_score >= 90:
        return f"Severe chain risk at {stage}. Treat as active compromise until disproven."
    if risk_score >= 75:
        return f"High chain risk at {stage}. Escalation path should be investigated immediately."
    if risk_score >= 50:
        return f"Moderate chain risk at {stage}. Additional correlation is needed."
    return f"Observed activity at {stage}. Continue monitoring and enrichment."


def _chain_actions(stage: str, risk_score: int) -> list[str]:
    if stage in {"incident_escalation", "malware_execution"} or risk_score >= 90:
        return [
            "Open or escalate an incident response case.",
            "Isolate affected assets and preserve forensic evidence.",
            "Review identity, endpoint, and network telemetry around the chain.",
        ]
    if stage in {"credential_access_escalation", "brute_force_detected"}:
        return [
            "Block source IP or enforce conditional access controls.",
            "Reset affected credentials and validate MFA enforcement.",
            "Search for successful logins after failed attempts.",
        ]
    return [
        "Validate whether events share timing, source, or asset context.",
        "Run threat enrichment and check graph neighbors.",
        "Monitor for additional alerts from the same source.",
    ]


def _chain_mitre(stage: str) -> str:
    if stage in {"credential_access_escalation", "brute_force_detected"}:
        return "This chain aligns with Credential Access behavior such as T1110 Brute Force."
    if stage in {"malware_execution", "malware_indicator"}:
        return "This chain may align with Execution and malware delivery behaviors."
    if stage == "incident_escalation":
        return "The chain spans detection and response stages; map individual alerts to ATT&CK techniques."
    return "No single MITRE technique is confirmed for this chain yet."
