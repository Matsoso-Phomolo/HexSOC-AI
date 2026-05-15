"""Deterministic incident escalation from HexSOC intelligence objects."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.db import models


OPEN_INCIDENT_STATUSES = {"open", "investigating", "contained"}
CRITICAL_STAGES = [
    ("Credential Access", "Command and Control"),
    ("Lateral Movement", "Credential Access"),
]


def escalate_attack_chain(db: Session, chain: dict[str, Any], recommendation: dict[str, Any]) -> dict[str, Any]:
    """Create or update an incident for a high-risk attack chain."""
    return _escalate(
        db,
        entity_type="attack_chain",
        entity_id=str(chain.get("chain_id") or chain.get("id") or "unknown"),
        context=chain,
        recommendation=recommendation,
    )


def escalate_campaign(db: Session, campaign: dict[str, Any], recommendation: dict[str, Any]) -> dict[str, Any]:
    """Create or update an incident for a high-risk campaign cluster."""
    return _escalate(
        db,
        entity_type="campaign",
        entity_id=str(campaign.get("campaign_id") or campaign.get("id") or "unknown"),
        context=campaign,
        recommendation=recommendation,
    )


def escalate_context(
    db: Session,
    *,
    entity_type: str,
    entity_id: str,
    context: dict[str, Any],
    recommendation: dict[str, Any],
) -> dict[str, Any]:
    """Create or update an incident for caller-supplied bounded context."""
    return _escalate(db, entity_type=entity_type, entity_id=entity_id, context=context, recommendation=recommendation)


def should_escalate(context: dict[str, Any], recommendation: dict[str, Any] | None = None) -> tuple[bool, str]:
    """Return whether context meets deterministic escalation criteria."""
    recommendation = recommendation or {}
    risk_score = _risk_score(context)
    classification = str(context.get("classification") or context.get("severity") or "").lower()
    stages = set(_safe_list(context.get("stages") or context.get("mitre_tactics")))
    related_alerts = context.get("related_alerts") or {}
    critical_alert_count = int(related_alerts.get("critical_count") or 0) if isinstance(related_alerts, dict) else 0

    if risk_score >= 75:
        return True, f"Risk score {risk_score} meets critical escalation threshold."
    if classification == "critical":
        return True, "Classification is critical."
    for left, right in CRITICAL_STAGES:
        if left in stages and right in stages:
            return True, f"Attack chain contains {left} and {right}."
    if recommendation.get("escalation_required") is True:
        return True, "Investigation recommendation requires escalation."
    if critical_alert_count >= 2:
        return True, "Multiple critical alerts are linked to the same investigation context."
    return False, "Escalation criteria not met."


def _escalate(
    db: Session,
    *,
    entity_type: str,
    entity_id: str,
    context: dict[str, Any],
    recommendation: dict[str, Any],
) -> dict[str, Any]:
    escalation_required, reason = should_escalate(context, recommendation)
    priority = _priority(context, recommendation)
    if not escalation_required:
        return _result(False, False, None, reason, priority, entity_type, entity_id, recommendation)

    marker = _marker(entity_type, entity_id)
    existing = _find_existing_incident(db, marker)
    if existing:
        _update_incident(existing, context, recommendation, reason, priority, marker)
        return _result(True, False, existing.id, reason, priority, entity_type, entity_id, recommendation)

    incident = models.Incident(
        title=_title(entity_type, entity_id, context),
        severity="critical" if priority == "critical" else "high",
        status="open",
        summary=_summary(context, recommendation, reason),
        description=_description(context, recommendation, reason, marker),
        priority=priority,
        case_status="open",
        escalation_level=priority,
    )
    db.add(incident)
    db.flush()
    return _result(True, True, incident.id, reason, priority, entity_type, entity_id, recommendation)


def _find_existing_incident(db: Session, marker: str) -> models.Incident | None:
    return (
        db.query(models.Incident)
        .filter(models.Incident.description.ilike(f"%{marker}%"))
        .filter(models.Incident.status.in_(OPEN_INCIDENT_STATUSES))
        .order_by(models.Incident.id.desc())
        .first()
    )


def _update_incident(
    incident: models.Incident,
    context: dict[str, Any],
    recommendation: dict[str, Any],
    reason: str,
    priority: str,
    marker: str,
) -> None:
    incident.priority = _max_priority(incident.priority, priority)
    incident.severity = "critical" if incident.priority == "critical" else incident.severity or "high"
    incident.case_status = incident.case_status or incident.status or "open"
    incident.escalation_level = _max_priority(incident.escalation_level, priority)
    incident.summary = _summary(context, recommendation, reason)
    if marker not in (incident.description or ""):
        incident.description = f"{incident.description or ''}\n\n{_description(context, recommendation, reason, marker)}".strip()


def _result(
    escalated: bool,
    created: bool,
    incident_id: int | None,
    reason: str,
    priority: str,
    entity_type: str,
    entity_id: str,
    recommendation: dict[str, Any],
) -> dict[str, Any]:
    return {
        "escalated": escalated,
        "created": created,
        "incident_id": incident_id,
        "reason": reason,
        "priority": priority,
        "linked_entity_type": entity_type,
        "linked_entity_id": entity_id,
        "recommended_next_steps": _safe_list(recommendation.get("analyst_next_steps"))[:10],
    }


def _title(entity_type: str, entity_id: str, context: dict[str, Any]) -> str:
    label = entity_type.replace("_", " ").title()
    source = context.get("source_value") or context.get("primary_source_ip") or context.get("title") or entity_id
    return f"{label} escalation: {source}"[:255]


def _summary(context: dict[str, Any], recommendation: dict[str, Any], reason: str) -> str:
    return recommendation.get("summary") or context.get("summary") or reason


def _description(context: dict[str, Any], recommendation: dict[str, Any], reason: str, marker: str) -> str:
    actions = "\n".join(f"- {item}" for item in _safe_list(recommendation.get("recommended_actions"))[:8])
    evidence = "\n".join(f"- {item}" for item in _safe_list(recommendation.get("evidence_to_collect"))[:8])
    return (
        f"{marker}\n"
        f"Escalation reason: {reason}\n\n"
        f"Recommended actions:\n{actions or '- Validate related telemetry.'}\n\n"
        f"Evidence to collect:\n{evidence or '- Preserve attack-chain timeline and alerts.'}"
    )


def _marker(entity_type: str, entity_id: str) -> str:
    return f"[hexsoc-escalation:{entity_type}:{entity_id}]"


def _risk_score(context: dict[str, Any]) -> int:
    try:
        return max(0, min(int(context.get("risk_score") or context.get("max_risk_score") or 0), 100))
    except (TypeError, ValueError):
        return 0


def _priority(context: dict[str, Any], recommendation: dict[str, Any]) -> str:
    priority = str(recommendation.get("priority") or "").lower()
    if priority in {"critical", "high", "medium", "low"}:
        return priority
    score = _risk_score(context)
    if score >= 85:
        return "critical"
    if score >= 75:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def _max_priority(left: str | None, right: str | None) -> str:
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    left_value = (left or "low").lower()
    right_value = (right or "low").lower()
    return left_value if rank.get(left_value, 0) >= rank.get(right_value, 0) else right_value


def _safe_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]
