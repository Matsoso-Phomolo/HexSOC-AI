from sqlalchemy.orm import Session

from app.db import models
from app.services.activity_service import add_activity


DEMO_MARKER = "hexsoc-demo"


DEMO_ASSETS = [
    {
        "hostname": "prod-web-01",
        "ip_address": "10.0.0.10",
        "operating_system": "Ubuntu Server",
        "role": "Web Server",
        "status": "active",
        "asset_type": "server",
        "environment": "production",
        "criticality": "high",
        "owner": "Platform Engineering",
    },
    {
        "hostname": "corp-dc-01",
        "ip_address": "10.0.1.5",
        "operating_system": "Windows Server 2022",
        "role": "Domain Controller",
        "status": "active",
        "asset_type": "server",
        "environment": "production",
        "criticality": "critical",
        "owner": "Identity Operations",
    },
    {
        "hostname": "finance-laptop-07",
        "ip_address": "10.0.22.47",
        "operating_system": "Windows 11 Enterprise",
        "role": "Finance Workstation",
        "status": "monitored",
        "asset_type": "endpoint",
        "environment": "corporate",
        "criticality": "medium",
        "owner": "Finance",
    },
]

DEMO_EVENTS = [
    {
        "event_type": "failed_login_spike",
        "source": "windows_event_logs",
        "source_ip": "203.0.113.45",
        "destination_ip": "10.0.1.5",
        "username": "administrator",
        "raw_message": "42 failed login attempts detected against domain controller.",
        "summary": "Failed login spike against domain controller.",
        "severity": "high",
    },
    {
        "event_type": "suspicious_ip_connection",
        "source": "network_sensor",
        "source_ip": "10.0.0.10",
        "destination_ip": "198.51.100.77",
        "username": "www-data",
        "raw_message": "Outbound connection to suspicious reputation IP.",
        "summary": "Production web server contacted suspicious external IP.",
        "severity": "medium",
    },
    {
        "event_type": "malware_alert",
        "source": "endpoint_edr",
        "source_ip": "10.0.22.47",
        "destination_ip": None,
        "username": "finance.user",
        "raw_message": "EDR quarantined Trojan.GenericKD payload.",
        "summary": "Malware quarantined on finance endpoint.",
        "severity": "critical",
    },
    {
        "event_type": "brute_force_attempt",
        "source": "vpn_gateway",
        "source_ip": "192.0.2.118",
        "destination_ip": "10.0.1.5",
        "username": "svc_backup",
        "raw_message": "Repeated VPN authentication failures for service account.",
        "summary": "Possible brute force attempt against VPN.",
        "severity": "high",
    },
    {
        "event_type": "unusual_admin_login",
        "source": "identity_provider",
        "source_ip": "198.51.100.23",
        "destination_ip": "10.0.1.5",
        "username": "admin.ops",
        "raw_message": "Admin login from new geography outside normal hours.",
        "summary": "Unusual privileged login detected.",
        "severity": "medium",
    },
]

DEMO_ALERTS = [
    {
        "title": "Failed login spike on domain controller",
        "description": "Multiple failed administrator logins observed against corp-dc-01.",
        "severity": "high",
        "status": "new",
        "source": DEMO_MARKER,
    },
    {
        "title": "Malware quarantined on finance endpoint",
        "description": "EDR reported a critical malware quarantine on finance-laptop-07.",
        "severity": "critical",
        "status": "investigating",
        "source": DEMO_MARKER,
    },
    {
        "title": "Suspicious outbound connection from production web server",
        "description": "prod-web-01 connected to an external IP with poor reputation.",
        "severity": "medium",
        "status": "new",
        "source": DEMO_MARKER,
    },
]

DEMO_INCIDENTS = [
    {
        "title": "Credential attack investigation",
        "description": "Correlates failed login spike and VPN brute force activity.",
        "summary": "Credential attack investigation across identity controls.",
        "severity": "high",
        "status": "investigating",
    },
    {
        "title": "Endpoint malware containment",
        "description": "Finance endpoint malware event requires validation and containment review.",
        "summary": "EDR malware containment workflow for finance endpoint.",
        "severity": "critical",
        "status": "contained",
    },
]


def seed_demo_data(db: Session) -> dict[str, dict[str, int]]:
    """Insert portfolio-ready SOC demo data once."""
    result = {
        "assets": {"created": 0, "skipped": 0},
        "events": {"created": 0, "skipped": 0},
        "alerts": {"created": 0, "skipped": 0},
        "incidents": {"created": 0, "skipped": 0},
        "activity": {"created": 0, "skipped": 0},
    }

    assets_by_hostname = {
        asset.hostname: asset for asset in db.query(models.Asset).filter(
            models.Asset.hostname.in_([item["hostname"] for item in DEMO_ASSETS]),
        )
    }

    for payload in DEMO_ASSETS:
        if payload["hostname"] in assets_by_hostname:
            result["assets"]["skipped"] += 1
            continue

        asset = models.Asset(**payload)
        db.add(asset)
        db.flush()
        add_activity(
            db,
            action="asset_created",
            entity_type="asset",
            entity_id=asset.id,
            message=f"Demo asset created: {asset.hostname}",
            severity="info",
        )
        result["assets"]["created"] += 1
        result["activity"]["created"] += 1

    for payload in DEMO_EVENTS:
        exists = (
            db.query(models.SecurityEvent)
            .filter(
                models.SecurityEvent.source == payload["source"],
                models.SecurityEvent.event_type == payload["event_type"],
                models.SecurityEvent.raw_message == payload["raw_message"],
            )
            .first()
        )
        if exists:
            result["events"]["skipped"] += 1
            continue

        event = models.SecurityEvent(**payload, raw_payload={"demo": True, "marker": DEMO_MARKER})
        db.add(event)
        db.flush()
        add_activity(
            db,
            action="event_created",
            entity_type="security_event",
            entity_id=event.id,
            message=f"Demo event created: {event.event_type}",
            severity=event.severity,
        )
        result["events"]["created"] += 1
        result["activity"]["created"] += 1

    for payload in DEMO_ALERTS:
        exists = db.query(models.Alert).filter(models.Alert.title == payload["title"]).first()
        if exists:
            result["alerts"]["skipped"] += 1
            continue

        alert = models.Alert(**payload)
        db.add(alert)
        db.flush()
        add_activity(
            db,
            action="alert_created",
            entity_type="alert",
            entity_id=alert.id,
            message=f"Demo alert created: {alert.title}",
            severity=alert.severity,
        )
        result["alerts"]["created"] += 1
        result["activity"]["created"] += 1

    for payload in DEMO_INCIDENTS:
        exists = db.query(models.Incident).filter(models.Incident.title == payload["title"]).first()
        if exists:
            result["incidents"]["skipped"] += 1
            continue

        incident = models.Incident(**payload)
        db.add(incident)
        db.flush()
        add_activity(
            db,
            action="incident_created",
            entity_type="incident",
            entity_id=incident.id,
            message=f"Demo incident created: {incident.title}",
            severity=incident.severity,
        )
        result["incidents"]["created"] += 1
        result["activity"]["created"] += 1

    db.commit()
    return result
