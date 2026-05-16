"""WebSocket connection manager for real-time SOC dashboard updates."""

from datetime import datetime, timezone
from typing import Any

from fastapi import WebSocket
from sqlalchemy.orm import Session

from app.db import models


def _iso_datetime(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def serialize_alert(alert: Any) -> dict[str, Any]:
    """Convert an Alert ORM object into a WebSocket-safe payload."""
    return {
        "id": alert.id,
        "title": alert.title,
        "severity": alert.severity,
        "status": alert.status,
        "source": alert.source,
        "description": alert.description,
        "event_id": alert.event_id,
        "mitre_tactic": alert.mitre_tactic,
        "mitre_technique": alert.mitre_technique,
        "confidence_score": alert.confidence_score,
        "detection_rule": alert.detection_rule,
        "threat_source": alert.threat_source,
        "threat_score": alert.threat_score,
        "geo_country": alert.geo_country,
        "geo_city": alert.geo_city,
        "isp": alert.isp,
        "enrichment_status": alert.enrichment_status,
        "created_at": _iso_datetime(alert.created_at),
        "updated_at": _iso_datetime(alert.updated_at),
    }


def serialize_activity(activity: Any) -> dict[str, Any]:
    """Convert an ActivityLog ORM object into a WebSocket-safe payload."""
    return {
        "id": activity.id,
        "action": activity.action,
        "entity_type": activity.entity_type,
        "entity_id": activity.entity_id,
        "message": activity.message,
        "severity": activity.severity,
        "actor_username": activity.actor_username,
        "actor_role": activity.actor_role,
        "created_at": _iso_datetime(activity.created_at),
    }


class WebSocketManager:
    """Track active dashboard clients and broadcast SOC updates."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and register a WebSocket client."""
        await websocket.accept()
        self.active_connections.append(websocket)
        await websocket.send_json(
            {
                "type": "connected",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "payload": {"message": "HexSOC real-time stream connected"},
            }
        )

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket client if it is still registered."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_alert(self, payload: dict[str, Any]) -> None:
        """Broadcast alert lifecycle events to connected dashboard clients."""
        await self._broadcast(payload)

    async def broadcast_activity(self, payload: dict[str, Any]) -> None:
        """Broadcast activity timeline events to connected dashboard clients."""
        await self._broadcast(payload)

    async def broadcast_event(self, event_type: str, payload: dict[str, Any] | None = None) -> None:
        """Broadcast a normalized event payload."""
        await self._broadcast({"type": event_type, **(payload or {})})

    async def broadcast_dashboard_metrics(self, db: Session) -> None:
        """Broadcast lightweight dashboard counter refresh hints."""
        await self.broadcast_event("dashboard_metrics_updated", build_dashboard_metrics(db))

    async def _broadcast(self, payload: dict[str, Any]) -> None:
        message = normalize_ws_message(payload)
        disconnected: list[WebSocket] = []

        for websocket in list(self.active_connections):
            try:
                await websocket.send_json(message)
            except Exception:
                disconnected.append(websocket)

        for websocket in disconnected:
            self.disconnect(websocket)


websocket_manager = WebSocketManager()


def normalize_ws_message(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize all outbound messages to the shared realtime envelope."""
    event_type = payload.get("type", "message")
    if "payload" in payload and set(payload.keys()).issubset({"type", "timestamp", "payload"}):
        return {
            "type": event_type,
            "timestamp": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "payload": payload.get("payload") or {},
        }
    return {
        "type": event_type,
        "timestamp": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "payload": {key: value for key, value in payload.items() if key not in {"type", "timestamp"}},
    }


def serialize_collector(collector: Any) -> dict[str, Any]:
    """Convert a Collector ORM object into a WebSocket-safe payload."""
    return {
        "id": collector.id,
        "name": collector.name,
        "collector_type": collector.collector_type,
        "source_label": collector.source_label,
        "is_active": collector.is_active,
        "last_seen_at": _iso_datetime(collector.last_seen_at),
        "agent_version": collector.agent_version,
        "host_name": collector.host_name,
        "os_name": collector.os_name,
        "os_version": collector.os_version,
        "last_event_count": collector.last_event_count,
        "last_error": collector.last_error,
        "heartbeat_count": collector.heartbeat_count,
        "last_heartbeat_at": _iso_datetime(collector.last_heartbeat_at),
        "health_status": collector.health_status,
        "revoked_at": _iso_datetime(collector.revoked_at),
    }


def build_dashboard_metrics(db: Session) -> dict[str, Any]:
    """Build lightweight dashboard counters for realtime refresh hints."""
    collectors = db.query(models.Collector).order_by(models.Collector.id.desc()).limit(500).all()
    health_counts = {"online": 0, "degraded": 0, "stale": 0, "offline": 0, "revoked": 0}
    for collector in collectors:
        status = collector.health_status or "offline"
        status = "degraded" if status == "online" and collector.last_error else status
        health_counts[status if status in health_counts else "offline"] += 1
    return {
        "assets_count": db.query(models.Asset).count(),
        "events_count": db.query(models.SecurityEvent).count(),
        "alerts_count": db.query(models.Alert).count(),
        "incidents_count": db.query(models.Incident).count(),
        "collectors_health_summary": {
            "total_collectors": len(collectors),
            **health_counts,
        },
    }
