"""MITRE ATT&CK mapping helpers for telemetry and detections."""

from collections import Counter
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from app.db import models


@dataclass(frozen=True)
class MitreMapping:
    tactic: str
    technique: str
    technique_id: str
    confidence: int
    reason: str


EVENT_MAPPINGS: dict[str, MitreMapping] = {
    "failed_login": MitreMapping("Credential Access", "Brute Force", "T1110", 90, "Failed authentication event indicates brute-force behavior."),
    "suspicious_powershell": MitreMapping("Execution", "PowerShell", "T1059.001", 92, "PowerShell command line contains suspicious execution indicators."),
    "credential_access": MitreMapping("Credential Access", "Credential Dumping", "T1003", 94, "Telemetry references LSASS, Mimikatz, sekurlsa, or process dumping."),
    "lateral_movement": MitreMapping("Lateral Movement", "Remote Services", "T1021", 88, "Telemetry references remote service, PsExec, WMIC, or WinRM behavior."),
    "service_installed": MitreMapping("Persistence", "Windows Service", "T1543.003", 84, "Windows service installation can indicate persistence or lateral movement."),
    "dns_suspicious": MitreMapping("Command and Control", "DNS", "T1071.004", 78, "Suspicious DNS pattern may indicate command-and-control traffic."),
    "malware_indicator": MitreMapping("Command and Control", "Ingress Tool Transfer", "T1105", 88, "Malware or beacon indicators suggest tool transfer or C2 staging."),
    "user_created": MitreMapping("Persistence", "Create Account", "T1136", 82, "User creation can provide persistence."),
    "user_added_to_privileged_group": MitreMapping("Persistence", "Account Manipulation", "T1098", 86, "Privileged group membership changes can indicate account manipulation."),
    "account_locked_out": MitreMapping("Credential Access", "Brute Force", "T1110", 72, "Account lockout can follow repeated authentication failures."),
}


RULE_MAPPINGS: dict[str, MitreMapping] = {
    "failed_login_spike": MitreMapping("Credential Access", "Brute Force", "T1110", 92, "Detection rule identified repeated failed authentication attempts."),
    "unusual_admin_login": MitreMapping("Defense Evasion", "Valid Accounts", "T1078", 86, "Privileged login pattern indicates possible valid-account abuse."),
    "malware_indicator": MitreMapping("Command and Control", "Ingress Tool Transfer", "T1105", 88, "Detection rule identified malware or beacon indicators."),
    "suspicious_ip_frequency": MitreMapping("Command and Control", "Application Layer Protocol", "T1071", 70, "High frequency activity from one source may indicate application-layer C2 or scanning."),
}


def map_event(event: models.SecurityEvent) -> MitreMapping | None:
    """Map one normalized event to MITRE ATT&CK."""
    event_type = (event.event_type or "").lower()
    text = _event_text(event)

    if event_type == "login_success" and any(token in (event.username or "").lower() for token in ("admin", "root", "administrator")):
        return MitreMapping("Defense Evasion", "Valid Accounts", "T1078", 84, "Successful privileged login may indicate valid-account abuse.")
    if event_type == "process_creation" and _is_suspicious_command(text):
        return MitreMapping("Execution", "Command and Scripting Interpreter", "T1059", 76, "Process command line contains suspicious interpreter behavior.")
    if any(token in text for token in ("mimikatz", "sekurlsa", "lsass", "procdump")):
        return EVENT_MAPPINGS["credential_access"]
    if any(token in text for token in ("psexec", "wmic", "winrm", "remote service")):
        return EVENT_MAPPINGS["lateral_movement"]
    if any(token in text for token in ("trojan", "ransomware", "beacon", "malware")):
        return EVENT_MAPPINGS["malware_indicator"]
    return EVENT_MAPPINGS.get(event_type)


def map_alert(alert: models.Alert) -> MitreMapping | None:
    """Map one alert to MITRE ATT&CK from detection rule or alert text."""
    rule = (alert.detection_rule or "").split(":", 1)[0].lower()
    if rule in RULE_MAPPINGS:
        return RULE_MAPPINGS[rule]
    text = " ".join(str(value or "") for value in (alert.title, alert.description, alert.mitre_technique)).lower()
    if "brute" in text or "failed login" in text:
        return RULE_MAPPINGS["failed_login_spike"]
    if "malware" in text or "beacon" in text:
        return RULE_MAPPINGS["malware_indicator"]
    return None


def apply_event_mapping(event: models.SecurityEvent) -> bool:
    mapping = map_event(event)
    if not mapping:
        return False
    event.mitre_tactic = mapping.tactic
    event.mitre_technique = mapping.technique
    event.mitre_technique_id = mapping.technique_id
    event.mitre_confidence = mapping.confidence
    event.mitre_reason = mapping.reason
    return True


def apply_alert_mapping(alert: models.Alert) -> bool:
    mapping = map_alert(alert)
    if not mapping:
        return False
    alert.mitre_tactic = mapping.tactic
    alert.mitre_technique = mapping.technique
    alert.mitre_technique_id = mapping.technique_id
    alert.confidence_score = max(alert.confidence_score or 0, mapping.confidence)
    return True


def map_unmapped_events(db: Session, limit: int = 500) -> int:
    events = (
        db.query(models.SecurityEvent)
        .filter(models.SecurityEvent.mitre_technique_id.is_(None))
        .order_by(models.SecurityEvent.id.desc())
        .limit(limit)
        .all()
    )
    mapped = sum(1 for event in events if apply_event_mapping(event))
    db.commit()
    return mapped


def map_unmapped_alerts(db: Session, limit: int = 500) -> int:
    alerts = (
        db.query(models.Alert)
        .filter(models.Alert.mitre_technique_id.is_(None))
        .order_by(models.Alert.id.desc())
        .limit(limit)
        .all()
    )
    mapped = sum(1 for alert in alerts if apply_alert_mapping(alert))
    db.commit()
    return mapped


def coverage_summary(db: Session) -> dict[str, Any]:
    events = db.query(models.SecurityEvent).all()
    alerts = db.query(models.Alert).all()
    event_techniques = [event.mitre_technique_id for event in events if event.mitre_technique_id]
    alert_techniques = [alert.mitre_technique_id for alert in alerts if alert.mitre_technique_id]
    tactics = [event.mitre_tactic for event in events if event.mitre_tactic] + [alert.mitre_tactic for alert in alerts if alert.mitre_tactic]

    return {
        "total_events": len(events),
        "mapped_events": len(event_techniques),
        "total_alerts": len(alerts),
        "mapped_alerts": len(alert_techniques),
        "top_techniques": _counter_list(event_techniques + alert_techniques),
        "top_tactics": _counter_list(tactics),
    }


def _event_text(event: models.SecurityEvent) -> str:
    return " ".join(
        str(value or "")
        for value in (
            event.event_type,
            event.username,
            event.raw_message,
            event.summary,
            event.raw_payload,
        )
    ).lower()


def _is_suspicious_command(text: str) -> bool:
    return any(token in text for token in ("powershell", "-enc", "encodedcommand", "iex", "downloadstring", "cmd.exe", "wscript", "cscript"))


def _counter_list(values: list[str]) -> list[dict[str, Any]]:
    return [{"name": name, "count": count} for name, count in Counter(values).most_common(8)]
