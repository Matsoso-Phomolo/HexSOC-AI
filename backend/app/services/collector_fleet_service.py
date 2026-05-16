"""Collector fleet health summaries and operational grouping."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.db import models
from app.services.collector_service import calculate_health_status, refresh_collector_health

DEFAULT_FLEET_LIMIT = 100
MAX_FLEET_LIMIT = 500
LOCAL_CONTROL_NOTE = (
    "Cloud dashboard cannot start local agents directly. Use local shortcuts or Task Scheduler scripts "
    "on the endpoint for start/stop operations."
)


def bounded_limit(limit: int | None, default: int = DEFAULT_FLEET_LIMIT) -> int:
    """Clamp API list limits to protect memory and response size."""
    if limit is None:
        return default
    return max(1, min(int(limit), MAX_FLEET_LIMIT))


def list_collectors(db: Session, *, limit: int = DEFAULT_FLEET_LIMIT) -> list[models.Collector]:
    """Return bounded collectors ordered by recent activity."""
    safe_limit = bounded_limit(limit)
    collectors = (
        db.query(models.Collector)
        .order_by(models.Collector.id.desc())
        .limit(safe_limit)
        .all()
    )
    refresh_fleet_health(db, collectors)
    return collectors


def refresh_fleet_health(db: Session, collectors: list[models.Collector]) -> None:
    """Refresh derived health values for a bounded collector set."""
    changed = False
    now = datetime.now(timezone.utc)
    for collector in collectors:
        old_status, new_status = refresh_collector_health(collector, now=now)
        if old_status != new_status:
            changed = True
            db.add(collector)
    if changed:
        db.commit()


def summarize_fleet(db: Session, *, limit: int = DEFAULT_FLEET_LIMIT) -> dict:
    """Build a bounded fleet summary suitable for dashboard use."""
    collectors = list_collectors(db, limit=limit)
    now = datetime.now(timezone.utc)
    status_counts = {"online": 0, "degraded": 0, "stale": 0, "offline": 0, "revoked": 0}
    type_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    os_counts: Counter[str] = Counter()
    version_counts: Counter[str] = Counter()
    last_seen_ages: list[int] = []
    heartbeat_ages: list[int] = []

    for collector in collectors:
        status = collector.health_status or calculate_health_status(collector, now=now)
        status = "degraded" if status == "online" and collector.last_error else status
        status_counts[status if status in status_counts else "offline"] += 1
        type_counts[collector.collector_type or "unknown"] += 1
        source_counts[collector.source_label or collector.name or "unknown"] += 1
        os_counts[_os_key(collector)] += 1
        version_counts[collector.agent_version or "unknown"] += 1
        last_seen_age = age_seconds(collector.last_seen_at, now=now)
        heartbeat_age = age_seconds(collector.last_heartbeat_at, now=now)
        if last_seen_age is not None:
            last_seen_ages.append(last_seen_age)
        if heartbeat_age is not None:
            heartbeat_ages.append(heartbeat_age)

    latest_version = _latest_version(version_counts)
    version_drift = [
        collector
        for collector in collectors
        if collector.agent_version and latest_version and collector.agent_version != latest_version
    ][:25]
    stale_collectors = [collector for collector in collectors if (collector.health_status or "") == "stale"][:25]
    offline_collectors = [collector for collector in collectors if (collector.health_status or "") == "offline"][:25]

    return {
        "total_collectors": len(collectors),
        "status_counts": status_counts,
        "type_distribution": _counter_rows(type_counts),
        "source_distribution": _counter_rows(source_counts),
        "os_distribution": _counter_rows(os_counts),
        "version_distribution": _counter_rows(version_counts),
        "stale_collectors": stale_collectors,
        "offline_collectors": offline_collectors,
        "version_drift": version_drift,
        "telemetry_volume_total": sum(int(collector.last_event_count or 0) for collector in collectors),
        "last_seen_age_seconds_max": max(last_seen_ages) if last_seen_ages else None,
        "heartbeat_age_seconds_max": max(heartbeat_ages) if heartbeat_ages else None,
    }


def collector_detail(db: Session, collector_id: int) -> dict | None:
    """Return one collector with derived fleet metadata."""
    collector = db.get(models.Collector, collector_id)
    if collector is None:
        return None
    refresh_fleet_health(db, [collector])
    now = datetime.now(timezone.utc)
    latest_version = _latest_version(
        Counter(
            version
            for (version,) in db.query(models.Collector.agent_version)
            .filter(models.Collector.agent_version.isnot(None))
            .limit(MAX_FLEET_LIMIT)
            .all()
        )
    )
    return {
        "collector": collector,
        "last_seen_age_seconds": age_seconds(collector.last_seen_at, now=now),
        "heartbeat_age_seconds": age_seconds(collector.last_heartbeat_at, now=now),
        "telemetry_volume": int(collector.last_event_count or 0),
        "version_drift": bool(collector.agent_version and latest_version and collector.agent_version != latest_version),
        "local_control_note": LOCAL_CONTROL_NOTE,
    }


def offline_collectors(db: Session, *, limit: int = DEFAULT_FLEET_LIMIT) -> list[models.Collector]:
    """Return bounded stale/offline/revoked collectors."""
    collectors = list_collectors(db, limit=limit)
    return [
        collector
        for collector in collectors
        if (collector.health_status or calculate_health_status(collector)) in {"stale", "offline", "revoked"}
    ]


def version_drift_collectors(db: Session, *, limit: int = DEFAULT_FLEET_LIMIT) -> list[models.Collector]:
    """Return collectors not running the most common/latest reported agent version."""
    collectors = list_collectors(db, limit=limit)
    version_counts = Counter(collector.agent_version for collector in collectors if collector.agent_version)
    latest_version = _latest_version(version_counts)
    if not latest_version:
        return []
    return [collector for collector in collectors if collector.agent_version and collector.agent_version != latest_version]


def age_seconds(value: datetime | None, *, now: datetime | None = None) -> int | None:
    """Return positive age in seconds for datetimes that may be naive."""
    if value is None:
        return None
    current = now or datetime.now(timezone.utc)
    observed = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    return max(0, int((current - observed).total_seconds()))


def _counter_rows(counter: Counter[str], limit: int = 10) -> list[dict[str, int | str]]:
    return [{"key": key, "count": count} for key, count in counter.most_common(limit)]


def _os_key(collector: models.Collector) -> str:
    parts = [collector.os_name, collector.os_version]
    return " ".join(part for part in parts if part) or "unknown"


def _latest_version(version_counts: Counter[str | None]) -> str | None:
    versions = [version for version in version_counts if version]
    if not versions:
        return None
    return sorted(versions)[-1]
