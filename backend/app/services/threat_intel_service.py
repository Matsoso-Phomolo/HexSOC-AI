"""Threat intelligence enrichment for alerts and security events."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db import models
from app.services.activity_service import add_activity


@dataclass
class ThreatIntelResult:
    """Normalized enrichment result across external and local providers."""

    source_ip: str
    risk_score: int
    country: str | None = None
    city: str | None = None
    isp: str | None = None
    asn: str | None = None
    known_malicious: bool = False
    abuse_confidence_score: int | None = None
    total_reports: int | None = None
    last_reported_at: datetime | None = None
    threat_source: str = "local_fallback"
    status: str = "fallback"


def enrich_security_context(db: Session) -> dict[str, Any]:
    """Enrich stored events and alerts that have source IP context."""
    events = db.query(models.SecurityEvent).filter(models.SecurityEvent.source_ip.isnot(None)).all()
    alerts = db.query(models.Alert).all()
    results_by_ip: dict[str, ThreatIntelResult] = {}
    event_updates = 0
    alert_updates = 0
    created_activities: list[models.ActivityLog] = []

    for event in events:
        if not event.source_ip:
            continue

        result = results_by_ip.setdefault(event.source_ip, enrich_source_ip(event.source_ip))
        apply_event_enrichment(event, result)
        event_updates += 1

    for alert in alerts:
        source_ip = get_alert_source_ip(db, alert)
        if not source_ip:
            continue

        result = results_by_ip.setdefault(source_ip, enrich_source_ip(source_ip))
        apply_alert_enrichment(alert, result)
        alert_updates += 1

    created_activities.append(
        add_activity(
            db,
            action="threat_intel_enrichment",
            entity_type="threat_intel",
            entity_id=None,
            message=(
                f"Threat intelligence enrichment processed {len(results_by_ip)} source IPs, "
                f"{event_updates} events, and {alert_updates} alerts."
            ),
            severity="info",
        )
    )

    db.commit()
    for activity in created_activities:
        db.refresh(activity)

    return {
        "source_ips_checked": len(results_by_ip),
        "events_enriched": event_updates,
        "alerts_enriched": alert_updates,
        "providers": _enabled_providers(),
        "activities": created_activities,
    }


def enrich_alert_if_source_ip(db: Session, alert: models.Alert) -> ThreatIntelResult | None:
    """Enrich a newly created detection alert when source IP context is available."""
    source_ip = get_alert_source_ip(db, alert)
    if not source_ip:
        alert.enrichment_status = "no_source_ip"
        return None

    result = enrich_source_ip(source_ip)
    apply_alert_enrichment(alert, result)
    event = db.get(models.SecurityEvent, alert.event_id) if alert.event_id else None
    if event:
        apply_event_enrichment(event, result)
    return result


def enrich_source_ip(source_ip: str) -> ThreatIntelResult:
    """Build a normalized threat intelligence result for one source IP."""
    try:
        ipaddress.ip_address(source_ip)
    except ValueError:
        return ThreatIntelResult(
            source_ip=source_ip,
            risk_score=0,
            country="Invalid",
            isp="Invalid IP",
            asn="invalid",
            threat_source="local_fallback",
            status="invalid_ip",
        )

    fallback = _fallback_result(source_ip)
    abuse = _query_abuseipdb(source_ip)
    vt = _query_virustotal(source_ip)
    geo = _query_geoip(source_ip)

    risk_score = max(
        fallback.risk_score,
        int(abuse.get("abuse_confidence_score") or 0),
        int(vt.get("risk_score") or 0),
    )
    total_reports = abuse.get("total_reports")
    known_malicious = bool(risk_score >= 70 or vt.get("known_malicious"))

    return ThreatIntelResult(
        source_ip=source_ip,
        risk_score=min(risk_score, 100),
        country=geo.get("country") or abuse.get("country") or fallback.country,
        city=geo.get("city") or fallback.city,
        isp=geo.get("isp") or abuse.get("isp") or fallback.isp,
        asn=geo.get("asn") or abuse.get("asn") or fallback.asn,
        known_malicious=known_malicious,
        abuse_confidence_score=abuse.get("abuse_confidence_score"),
        total_reports=total_reports,
        last_reported_at=_parse_datetime(abuse.get("last_reported_at")),
        threat_source=_source_label(abuse, vt, geo),
        status="enriched" if abuse or vt or geo else fallback.status,
    )


def apply_event_enrichment(event: models.SecurityEvent, result: ThreatIntelResult) -> None:
    """Persist normalized enrichment fields onto a security event."""
    event.risk_score = result.risk_score
    event.country = result.country
    event.isp = result.isp
    event.asn = result.asn
    event.known_malicious = result.known_malicious
    event.abuse_confidence_score = result.abuse_confidence_score
    event.total_reports = result.total_reports
    event.last_reported_at = result.last_reported_at


def apply_alert_enrichment(alert: models.Alert, result: ThreatIntelResult) -> None:
    """Persist normalized enrichment fields onto an alert."""
    alert.threat_source = result.threat_source
    alert.threat_score = result.risk_score
    alert.geo_country = result.country
    alert.geo_city = result.city
    alert.isp = result.isp
    alert.enrichment_status = result.status


def get_alert_source_ip(db: Session, alert: models.Alert) -> str | None:
    """Resolve source IP from linked event or detection rule source key."""
    if alert.event_id:
        event = db.get(models.SecurityEvent, alert.event_id)
        if event and event.source_ip:
            return event.source_ip

    detection_rule = alert.detection_rule or ""
    marker = "source_ip:"
    if marker in detection_rule:
        return detection_rule.split(marker, 1)[1].strip() or None

    return None


def _query_abuseipdb(source_ip: str) -> dict[str, Any]:
    if not settings.abuseipdb_api_key:
        return {}

    query = urlencode({"ipAddress": source_ip, "maxAgeInDays": 90, "verbose": "true"})
    response = _request_json(
        f"https://api.abuseipdb.com/api/v2/check?{query}",
        headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
    )
    data = response.get("data", {})
    if not data:
        return {}

    return {
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
        "asn": str(data.get("asn")) if data.get("asn") else None,
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "last_reported_at": data.get("lastReportedAt"),
    }


def _query_virustotal(source_ip: str) -> dict[str, Any]:
    if not settings.virustotal_api_key:
        return {}

    response = _request_json(
        f"https://www.virustotal.com/api/v3/ip_addresses/{source_ip}",
        headers={"x-apikey": settings.virustotal_api_key},
    )
    stats = response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    risk_score = min((malicious * 20) + (suspicious * 10), 100)

    return {
        "risk_score": risk_score,
        "known_malicious": risk_score >= 70,
    }


def _query_geoip(source_ip: str) -> dict[str, Any]:
    try:
        ip = ipaddress.ip_address(source_ip)
    except ValueError:
        return {}
    if ip.is_private or ip.is_loopback or ip.is_reserved:
        return {}

    response = _request_json(f"https://ipapi.co/{source_ip}/json/")
    if not response or response.get("error"):
        return {}

    return {
        "country": response.get("country_name") or response.get("country"),
        "city": response.get("city"),
        "isp": response.get("org"),
        "asn": response.get("asn"),
    }


def _request_json(url: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        request = Request(url, headers=headers or {})
        with urlopen(request, timeout=4) as response:
            return json.loads(response.read().decode("utf-8"))
    except (OSError, URLError, TimeoutError, json.JSONDecodeError):
        return {}


def _fallback_result(source_ip: str) -> ThreatIntelResult:
    ip = ipaddress.ip_address(source_ip)
    if ip.is_private or ip.is_loopback:
        return ThreatIntelResult(
            source_ip=source_ip,
            risk_score=5,
            country="Internal",
            city=None,
            isp="Private network",
            asn="internal",
            known_malicious=False,
            threat_source="local_fallback",
            status="internal",
        )

    if ip.is_reserved:
        return ThreatIntelResult(
            source_ip=source_ip,
            risk_score=15,
            country="Reserved",
            isp="Reserved range",
            asn="reserved",
            known_malicious=False,
            threat_source="local_fallback",
            status="fallback",
        )

    return ThreatIntelResult(
        source_ip=source_ip,
        risk_score=35,
        country="Unknown",
        isp="Unknown ISP",
        asn="unknown",
        known_malicious=False,
        threat_source="local_fallback",
        status="fallback",
    )


def _source_label(*provider_results: dict[str, Any]) -> str:
    labels = [
        label
        for label, result in zip(("abuseipdb", "virustotal", "geoip"), provider_results, strict=False)
        if result
    ]
    return ",".join(labels) if labels else "local_fallback"


def _enabled_providers() -> list[str]:
    providers = ["geoip", "shodan-ready"]
    if settings.abuseipdb_api_key:
        providers.append("abuseipdb")
    if settings.virustotal_api_key:
        providers.append("virustotal")
    if settings.shodan_api_key:
        providers.append("shodan")
    return providers


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
