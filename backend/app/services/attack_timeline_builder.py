"""Build compact, replay-ready timelines for attack-chain candidates."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


ATTACK_STAGES = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def build_timeline_steps(events: list[Any], alerts: list[Any]) -> list[dict[str, Any]]:
    """Return chronology across related events and alerts."""
    steps: list[dict[str, Any]] = []

    for event in events:
        payload = _safe_payload(event)
        steps.append(
            {
                "step_id": f"event:{event.id}",
                "entity_type": "event",
                "entity_id": event.id,
                "timestamp": _iso(_timestamp(event)),
                "event_type": event.event_type,
                "title": event.summary or event.event_type,
                "severity": event.severity,
                "attack_stage": infer_attack_stage(
                    event_type=event.event_type,
                    mitre_tactic=event.mitre_tactic,
                    mitre_technique_id=event.mitre_technique_id,
                    text=_join_text(event.summary, event.raw_message, payload),
                ),
                "mitre_tactic": event.mitre_tactic,
                "mitre_technique": event.mitre_technique,
                "mitre_technique_id": event.mitre_technique_id,
                "hostname": payload.get("hostname") or payload.get("computer") or payload.get("host_name"),
                "username": event.username,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "summary": event.summary or event.raw_message,
            }
        )

    for alert in alerts:
        steps.append(
            {
                "step_id": f"alert:{alert.id}",
                "entity_type": "alert",
                "entity_id": alert.id,
                "timestamp": _iso(_timestamp(alert)),
                "event_type": alert.detection_rule or "alert",
                "title": alert.title,
                "severity": alert.severity,
                "attack_stage": infer_attack_stage(
                    event_type=alert.detection_rule or alert.title,
                    mitre_tactic=alert.mitre_tactic,
                    mitre_technique_id=alert.mitre_technique_id,
                    text=_join_text(alert.title, alert.description),
                ),
                "mitre_tactic": alert.mitre_tactic,
                "mitre_technique": alert.mitre_technique,
                "mitre_technique_id": alert.mitre_technique_id,
                "hostname": None,
                "username": None,
                "source_ip": None,
                "destination_ip": None,
                "summary": alert.description,
            }
        )

    return sorted(steps, key=lambda step: step["timestamp"] or "")


def summarize_timeline(steps: list[dict[str, Any]]) -> dict[str, Any]:
    """Build compact analyst-facing timeline metadata."""
    stages = _ordered_unique(step["attack_stage"] for step in steps if step.get("attack_stage"))
    severities = [step.get("severity") or "info" for step in steps]
    highest = max(severities, key=lambda value: SEVERITY_RANK.get(value, 0), default="info")
    first_seen = steps[0]["timestamp"] if steps else None
    last_seen = steps[-1]["timestamp"] if steps else None
    return {
        "total_steps": len(steps),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "stages": stages,
        "highest_severity": highest,
        "summary": _timeline_sentence(stages, first_seen, last_seen),
    }


def infer_attack_stage(
    *,
    event_type: str | None,
    mitre_tactic: str | None = None,
    mitre_technique_id: str | None = None,
    text: str | None = None,
) -> str:
    """Map telemetry and MITRE metadata into a stable attack-chain stage."""
    tactic = (mitre_tactic or "").strip().lower()
    tactic_map = {
        "initial access": "Initial Access",
        "execution": "Execution",
        "persistence": "Persistence",
        "privilege escalation": "Privilege Escalation",
        "defense evasion": "Defense Evasion",
        "credential access": "Credential Access",
        "discovery": "Discovery",
        "lateral movement": "Lateral Movement",
        "command and control": "Command and Control",
        "exfiltration": "Exfiltration",
        "impact": "Impact",
    }
    if tactic in tactic_map:
        return tactic_map[tactic]

    combined = " ".join(
        value.lower()
        for value in [event_type or "", mitre_technique_id or "", text or ""]
        if value
    )
    if any(token in combined for token in ["failed_login", "brute", "t1110"]):
        return "Initial Access"
    if any(token in combined for token in ["powershell", "process_create", "process_creation", "t1059"]):
        return "Execution"
    if any(token in combined for token in ["service_installed", "registry", "user_created", "t1543", "t1136"]):
        return "Persistence"
    if any(token in combined for token in ["privilege", "admin_login", "administrator", "t1078", "t1098"]):
        return "Privilege Escalation"
    if any(token in combined for token in ["defense", "evasion", "encodedcommand", "-enc"]):
        return "Defense Evasion"
    if any(token in combined for token in ["credential", "lsass", "mimikatz", "procdump", "t1003"]):
        return "Credential Access"
    if any(token in combined for token in ["discovery", "whoami", "net user", "ipconfig"]):
        return "Discovery"
    if any(token in combined for token in ["lateral", "psexec", "wmic", "winrm", "t1021"]):
        return "Lateral Movement"
    if any(token in combined for token in ["dns", "network_connection", "beacon", "c2", "t1071", "t1105"]):
        return "Command and Control"
    if "exfil" in combined:
        return "Exfiltration"
    if any(token in combined for token in ["malware", "ransomware", "impact", "trojan"]):
        return "Impact"
    return "Discovery"


def _safe_payload(entity: Any) -> dict[str, Any]:
    payload = getattr(entity, "raw_payload", None)
    return payload if isinstance(payload, dict) else {}


def _timestamp(entity: Any) -> datetime:
    value = getattr(entity, "created_at", None) or getattr(entity, "updated_at", None)
    if isinstance(value, datetime):
        return value
    return datetime.min.replace(tzinfo=timezone.utc)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _join_text(*values: Any) -> str:
    parts: list[str] = []
    for value in values:
        if isinstance(value, dict):
            parts.extend(str(item) for item in value.values() if item is not None)
        elif value is not None:
            parts.append(str(value))
    return " ".join(parts)


def _ordered_unique(values: Any) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return [stage for stage in ATTACK_STAGES if stage in seen] + [
        stage for stage in result if stage not in ATTACK_STAGES
    ]


def _timeline_sentence(stages: list[str], first_seen: str | None, last_seen: str | None) -> str:
    if not stages:
        return "No attack-chain stages were identified."
    stage_text = " -> ".join(stages[:6])
    if len(stages) > 6:
        stage_text += " -> ..."
    if first_seen and last_seen:
        return f"Observed {stage_text} between {first_seen} and {last_seen}."
    return f"Observed {stage_text}."
