"""Deterministic SOC investigation recommendations for HexSOC intelligence objects."""

from __future__ import annotations

from typing import Any


MAX_ITEMS = 12


def recommend_for_attack_chain(chain: dict[str, Any]) -> dict[str, Any]:
    """Generate explainable recommendations for a persisted attack chain."""
    return _build_recommendation(
        entity_type="attack_chain",
        entity_id=str(chain.get("chain_id") or chain.get("id") or "unknown"),
        context=chain,
    )


def recommend_for_campaign(campaign: dict[str, Any]) -> dict[str, Any]:
    """Generate explainable recommendations for a campaign cluster."""
    return _build_recommendation(
        entity_type="campaign",
        entity_id=str(campaign.get("campaign_id") or campaign.get("id") or "unknown"),
        context=_campaign_as_context(campaign),
    )


def recommend_for_context(entity_type: str, entity_id: str | None, context: dict[str, Any]) -> dict[str, Any]:
    """Generate recommendations for caller-supplied alert, incident, campaign, or chain context."""
    return _build_recommendation(entity_type=entity_type, entity_id=entity_id or "ad_hoc", context=context)


def _build_recommendation(entity_type: str, entity_id: str, context: dict[str, Any]) -> dict[str, Any]:
    risk_score = _bounded_int(context.get("risk_score") or context.get("max_risk_score") or 0)
    classification = _classification(context.get("classification") or context.get("severity"), risk_score)
    priority = _priority(classification, risk_score)
    stages = _safe_list(context.get("stages") or context.get("mitre_tactics"))
    tactics = _safe_list(context.get("mitre_tactics"))
    techniques = _safe_list(context.get("mitre_techniques"))
    assets = _safe_list(context.get("affected_assets") or context.get("related_assets"))
    users = _safe_list(context.get("usernames") or context.get("related_users"))
    iocs = _safe_list(context.get("related_iocs") if isinstance(context.get("related_iocs"), list) else [])

    actions = _recommended_actions(priority, stages, tactics, techniques, assets, users)
    evidence = _evidence_to_collect(stages, tactics, techniques, assets, users, iocs)
    next_steps = _analyst_next_steps(priority, stages, entity_type)

    return {
        "entity_type": entity_type,
        "entity_id": entity_id,
        "risk_score": risk_score,
        "priority": priority,
        "classification": classification,
        "summary": _summary(entity_type, entity_id, priority, risk_score, stages, techniques),
        "recommended_actions": actions[:MAX_ITEMS],
        "evidence_to_collect": evidence[:MAX_ITEMS],
        "escalation_required": priority in {"critical", "high"},
        "mitre_context": _mitre_context(tactics, techniques),
        "analyst_next_steps": next_steps[:MAX_ITEMS],
        "analyst_notes": _analyst_notes(priority, assets, users, iocs),
        "response_priority": priority,
    }


def _campaign_as_context(campaign: dict[str, Any]) -> dict[str, Any]:
    return {
        "risk_score": campaign.get("risk_score") or campaign.get("max_risk_score"),
        "classification": campaign.get("classification"),
        "mitre_techniques": campaign.get("mitre_techniques") or campaign.get("shared_techniques"),
        "affected_assets": campaign.get("affected_assets") or campaign.get("shared_assets"),
        "usernames": campaign.get("usernames") or campaign.get("shared_users"),
        "related_iocs": campaign.get("shared_iocs"),
        "stages": campaign.get("mitre_tactics") or [],
    }


def _recommended_actions(
    priority: str,
    stages: list[Any],
    tactics: list[Any],
    techniques: list[Any],
    assets: list[Any],
    users: list[Any],
) -> list[str]:
    actions: list[str] = []
    if priority == "critical":
        actions.append("Initiate incident command workflow and assign a senior analyst immediately.")
        actions.append("Contain affected assets or network segments after validating business impact.")
    elif priority == "high":
        actions.append("Open an investigation session and assign ownership to an analyst.")
        actions.append("Validate whether related alerts represent a single intrusion path.")
    else:
        actions.append("Triage the related telemetry and monitor for additional stage progression.")

    normalized = _lower_join([*stages, *tactics, *techniques])
    if "credential" in normalized or "t1110" in normalized or "t1003" in normalized:
        actions.append("Reset or disable implicated credentials and review MFA, lockout, and privileged access logs.")
    if "lateral" in normalized or "t1021" in normalized:
        actions.append("Check remote service activity and isolate hosts showing lateral movement evidence.")
    if "command and control" in normalized or "t1071" in normalized or "t1105" in normalized:
        actions.append("Review egress traffic, DNS activity, proxy logs, and block confirmed command-and-control indicators.")
    if "impact" in normalized or "malware" in normalized or "ransomware" in normalized:
        actions.append("Prioritize containment, memory capture, malware quarantine, and recovery readiness checks.")
    if assets:
        actions.append("Validate criticality and ownership for all affected assets before containment.")
    if users:
        actions.append("Interview or validate activity for involved user accounts and check for impossible travel or privilege misuse.")
    return _dedupe(actions)


def _evidence_to_collect(
    stages: list[Any],
    tactics: list[Any],
    techniques: list[Any],
    assets: list[Any],
    users: list[Any],
    iocs: list[Any],
) -> list[str]:
    evidence = [
        "Preserve raw security events, alert records, and attack-chain timeline steps.",
        "Export authentication logs around the first_seen and last_seen window.",
        "Capture endpoint process, network, DNS, and file activity for involved hosts.",
    ]
    normalized = _lower_join([*stages, *tactics, *techniques])
    if "powershell" in normalized or "t1059" in normalized:
        evidence.append("Collect command-line history, PowerShell logs, script block logs, and parent-child process trees.")
    if "credential" in normalized or "t1003" in normalized:
        evidence.append("Collect LSASS access telemetry, credential provider logs, and privileged logon events.")
    if "lateral" in normalized or "t1021" in normalized:
        evidence.append("Collect SMB, WinRM, WMI, service creation, and remote logon evidence.")
    if iocs:
        evidence.append("Snapshot matched IOC records, source confidence, and relationship weights.")
    if assets:
        evidence.append("Record asset owner, business criticality, and containment decision rationale.")
    if users:
        evidence.append("Preserve user account group membership, recent password changes, and admin role assignments.")
    return _dedupe(evidence)


def _analyst_next_steps(priority: str, stages: list[Any], entity_type: str) -> list[str]:
    steps = [
        f"Confirm the {entity_type} scope and validate that related telemetry belongs to the same activity cluster.",
        "Compare MITRE stages against existing cases to avoid duplicate investigations.",
        "Document findings in a case note with containment and evidence decisions.",
    ]
    if priority in {"critical", "high"}:
        steps.insert(0, "Escalate to incident response lead and define containment owner.")
    if len(stages) >= 3:
        steps.append("Prepare an executive attack-chain summary because multiple stages are present.")
    return _dedupe(steps)


def _mitre_context(tactics: list[Any], techniques: list[Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    max_len = max(len(tactics), len(techniques), 1)
    for index in range(min(max_len, MAX_ITEMS)):
        tactic = str(tactics[index]) if index < len(tactics) else "Unknown tactic"
        technique = str(techniques[index]) if index < len(techniques) else "Unknown technique"
        rows.append({"tactic": tactic, "technique": technique})
    return rows


def _summary(entity_type: str, entity_id: str, priority: str, risk_score: int, stages: list[Any], techniques: list[Any]) -> str:
    stage_text = ", ".join(str(stage) for stage in stages[:4]) or "no explicit MITRE stage sequence"
    technique_text = ", ".join(str(technique) for technique in techniques[:4]) or "no mapped technique"
    return (
        f"{entity_type.replace('_', ' ').title()} {entity_id} is assessed as {priority} "
        f"with risk score {risk_score}. Observed context includes {stage_text}; mapped techniques include {technique_text}."
    )


def _analyst_notes(priority: str, assets: list[Any], users: list[Any], iocs: list[Any]) -> list[str]:
    notes = [f"Recommendation priority is {priority}; verify assumptions against raw telemetry before response."]
    if assets:
        notes.append(f"Affected assets observed: {len(assets)}.")
    if users:
        notes.append(f"Involved user accounts observed: {len(users)}.")
    if iocs:
        notes.append(f"Related IOC records observed: {len(iocs)}.")
    return notes


def _classification(value: Any, risk_score: int) -> str:
    normalized = str(value or "").lower()
    if normalized in {"critical", "high", "suspicious", "medium", "low", "info"}:
        return "suspicious" if normalized == "medium" else normalized
    if risk_score >= 75:
        return "critical"
    if risk_score >= 50:
        return "high"
    if risk_score >= 25:
        return "suspicious"
    return "low"


def _priority(classification: str, risk_score: int) -> str:
    if classification == "critical" or risk_score >= 85:
        return "critical"
    if classification == "high" or risk_score >= 60:
        return "high"
    if classification == "suspicious" or risk_score >= 25:
        return "medium"
    return "low"


def _bounded_int(value: Any) -> int:
    try:
        return max(0, min(int(value or 0), 100))
    except (TypeError, ValueError):
        return 0


def _safe_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value[:MAX_ITEMS]
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    return [value]


def _lower_join(values: list[Any]) -> str:
    return " ".join(str(value).lower() for value in values if value is not None)


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result
