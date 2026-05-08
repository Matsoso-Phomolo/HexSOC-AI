from collections import Counter
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.db import models
from app.services.activity_service import add_activity


@dataclass(frozen=True)
class DetectionMatch:
    rule: str
    source_key: str
    title: str
    description: str
    severity: str
    mitre_tactic: str
    mitre_technique: str
    confidence_score: int
    event_id: int | None = None


RULES = [
    "failed_login_spike",
    "suspicious_ip_frequency",
    "unusual_admin_login",
    "malware_indicator",
]


def run_detection_rules(db: Session, recent_limit: int = 250) -> dict[str, int]:
    """Run deterministic SOC detection rules against recent security events."""
    events = (
        db.query(models.SecurityEvent)
        .order_by(models.SecurityEvent.id.desc())
        .limit(recent_limit)
        .all()
    )
    matches = _find_matches(list(reversed(events)))
    alerts_created = 0

    add_activity(
        db,
        action="detection_run",
        entity_type="detection_engine",
        entity_id=None,
        message=f"Detection engine scanned {len(events)} recent events across {len(RULES)} rules.",
        severity="info",
    )

    for match in matches:
        if _alert_exists(db, match.rule, match.source_key):
            continue

        alert = models.Alert(
            title=match.title,
            description=f"{match.description} Source: {match.source_key}",
            severity=match.severity,
            status="new",
            source="detection_engine",
            event_id=match.event_id,
            mitre_tactic=match.mitre_tactic,
            mitre_technique=match.mitre_technique,
            confidence_score=match.confidence_score,
            detection_rule=f"{match.rule}:{match.source_key}",
        )
        db.add(alert)
        db.flush()
        add_activity(
            db,
            action="alert_created",
            entity_type="alert",
            entity_id=alert.id,
            message=f"Detection alert created by {match.rule}: {alert.title}",
            severity=alert.severity,
        )
        alerts_created += 1

    db.commit()

    return {
        "rules_checked": len(RULES),
        "alerts_created": alerts_created,
        "matches_found": len(matches),
    }


def _find_matches(events: list[models.SecurityEvent]) -> list[DetectionMatch]:
    matches: list[DetectionMatch] = []
    failed_login_events = [
        event for event in events if "failed_login" in (event.event_type or "").lower()
    ]

    failed_by_username = Counter(
        event.username.lower() for event in failed_login_events if event.username
    )
    failed_by_source_ip = Counter(event.source_ip for event in failed_login_events if event.source_ip)

    for username, count in failed_by_username.items():
        if count >= 5:
            event_id = _latest_event_id(failed_login_events, username=username)
            matches.append(
                DetectionMatch(
                    rule="failed_login_spike",
                    source_key=f"username:{username}",
                    title=f"Failed login spike for {username}",
                    description=f"{count} failed login events detected for the same username.",
                    severity="high",
                    mitre_tactic="Credential Access",
                    mitre_technique="T1110 Brute Force",
                    confidence_score=85,
                    event_id=event_id,
                )
            )

    for source_ip, count in failed_by_source_ip.items():
        if count >= 5:
            event_id = _latest_event_id(failed_login_events, source_ip=source_ip)
            matches.append(
                DetectionMatch(
                    rule="failed_login_spike",
                    source_key=f"source_ip:{source_ip}",
                    title=f"Failed login spike from {source_ip}",
                    description=f"{count} failed login events detected from the same source IP.",
                    severity="high",
                    mitre_tactic="Credential Access",
                    mitre_technique="T1110 Brute Force",
                    confidence_score=88,
                    event_id=event_id,
                )
            )

    source_ip_counts = Counter(event.source_ip for event in events if event.source_ip)
    for source_ip, count in source_ip_counts.items():
        if count >= 10:
            matches.append(
                DetectionMatch(
                    rule="suspicious_ip_frequency",
                    source_key=f"source_ip:{source_ip}",
                    title=f"High event frequency from {source_ip}",
                    description=f"{count} recent events share the same source IP.",
                    severity="medium",
                    mitre_tactic="Command and Control",
                    mitre_technique="T1059 Command and Scripting Interpreter",
                    confidence_score=65,
                    event_id=_latest_event_id(events, source_ip=source_ip),
                )
            )

    for event in events:
        event_type = (event.event_type or "").lower()
        username = (event.username or "").lower()
        raw_message = (event.raw_message or "").lower()

        if event_type in {"login_success", "unusual_login"} and any(
            admin_token in username for admin_token in ("admin", "root", "administrator")
        ):
            matches.append(
                DetectionMatch(
                    rule="unusual_admin_login",
                    source_key=f"username:{username or 'unknown'}",
                    title=f"Unusual privileged login for {event.username or 'unknown user'}",
                    description="Privileged account login matched unusual admin login rule.",
                    severity="high",
                    mitre_tactic="Defense Evasion",
                    mitre_technique="T1078 Valid Accounts",
                    confidence_score=82,
                    event_id=event.id,
                )
            )

        if "malware" in event_type or any(
            indicator in raw_message for indicator in ("malware", "trojan", "ransomware")
        ):
            matches.append(
                DetectionMatch(
                    rule="malware_indicator",
                    source_key=f"event:{event.id}",
                    title=f"Malware indicator detected in event {event.id}",
                    description="Malware keyword or event type matched detection rule.",
                    severity="critical",
                    mitre_tactic="Execution",
                    mitre_technique="T1204 User Execution",
                    confidence_score=92,
                    event_id=event.id,
                )
            )

    return matches


def _latest_event_id(events: list[models.SecurityEvent], **criteria: str) -> int | None:
    for event in reversed(events):
        if all(getattr(event, key) == value for key, value in criteria.items()):
            return event.id
    return None


def _alert_exists(db: Session, rule: str, source_key: str) -> bool:
    detection_rule = f"{rule}:{source_key}"
    return db.query(models.Alert).filter(models.Alert.detection_rule == detection_rule).first() is not None
