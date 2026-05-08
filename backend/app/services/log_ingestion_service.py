"""Normalize and persist external security telemetry."""

from datetime import datetime
from typing import Any

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.db import models
from app.schemas.ingestion import IngestLogItem, IngestedEventSummary
from app.services.activity_service import add_activity


ALLOWED_SEVERITIES = {"low", "medium", "high", "critical", "info"}


def ingest_logs(
    db: Session,
    logs: list[IngestLogItem],
    *,
    actor_username: str | None = None,
    actor_role: str | None = None,
) -> dict[str, Any]:
    """Store normalized logs as security events and create referenced assets."""
    summaries: list[IngestedEventSummary] = []
    created_assets = 0
    validation_errors: list[str] = []

    for index, log in enumerate(logs, start=1):
        if not log.event_type.strip():
            validation_errors.append(f"log[{index}] event_type is required")
            continue

        asset = _find_or_create_asset(db, log)
        if asset and asset.id is None:
            created_assets += 1
            db.flush()

        event = models.SecurityEvent(
            source=log.source.strip() or "external",
            event_type=log.event_type.strip(),
            severity=normalize_severity(log.severity),
            summary=_summary_for(log),
            source_ip=_clean(log.source_ip),
            destination_ip=_clean(log.destination_ip),
            username=_clean(log.username),
            raw_message=_clean(log.raw_message),
            asset_id=asset.id if asset else None,
            raw_payload=_build_raw_payload(log),
        )
        db.add(event)
        db.flush()
        summaries.append(
            IngestedEventSummary(
                event_id=event.id,
                event_type=event.event_type,
                severity=event.severity,
                asset_id=event.asset_id,
                hostname=log.hostname,
                source_ip=event.source_ip,
            )
        )

    activity = add_activity(
        db,
        action="bulk_log_ingestion_completed" if len(logs) > 1 else "log_ingested",
        entity_type="security_event",
        entity_id=summaries[-1].event_id if summaries else None,
        message=f"Ingested {len(summaries)} of {len(logs)} submitted log events.",
        severity="info" if not validation_errors else "warning",
        actor_username=actor_username,
        actor_role=actor_role,
    )
    db.commit()
    db.refresh(activity)

    return {
        "received": len(logs),
        "ingested": len(summaries),
        "skipped": len(logs) - len(summaries),
        "assets_created": created_assets,
        "events": summaries,
        "validation_errors": validation_errors,
        "_activity": activity,
    }


def normalize_severity(value: str | None) -> str:
    """Normalize common SIEM severity labels into HexSOC severities."""
    normalized = (value or "low").strip().lower()
    aliases = {
        "warn": "medium",
        "warning": "medium",
        "error": "high",
        "fatal": "critical",
        "severe": "critical",
        "informational": "info",
    }
    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in ALLOWED_SEVERITIES else "low"


def _find_or_create_asset(db: Session, log: IngestLogItem) -> models.Asset | None:
    hostname = _clean(log.hostname)
    ip_address = _clean(log.destination_ip) or _clean(log.source_ip)

    if not hostname and not ip_address:
        return None

    query = db.query(models.Asset)
    if hostname and ip_address:
        asset = query.filter(or_(models.Asset.hostname == hostname, models.Asset.ip_address == ip_address)).first()
    elif hostname:
        asset = query.filter(models.Asset.hostname == hostname).first()
    else:
        asset = query.filter(models.Asset.ip_address == ip_address).first()

    if asset:
        return asset

    asset = models.Asset(
        hostname=hostname or f"asset-{ip_address}",
        ip_address=ip_address,
        role="auto-discovered",
        status="monitored",
        asset_type="endpoint",
        environment="unknown",
        criticality="medium",
    )
    db.add(asset)
    return asset


def _build_raw_payload(log: IngestLogItem) -> dict[str, Any]:
    payload = dict(log.raw_payload or {})
    extra = log.model_extra or {}
    payload.update(extra)
    if log.timestamp:
        payload.setdefault("event_timestamp", log.timestamp.isoformat())
    if log.hostname:
        payload.setdefault("hostname", log.hostname)
    return payload


def _summary_for(log: IngestLogItem) -> str | None:
    if log.raw_message:
        return log.raw_message[:500]
    parts = [log.event_type, log.hostname, log.source_ip, log.username]
    return " | ".join(part for part in parts if part)[:500] or None


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None
