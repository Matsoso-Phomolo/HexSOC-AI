"""WebSocket connection manager for real-time SOC dashboard updates."""

from datetime import datetime
from typing import Any

from fastapi import WebSocket


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
                "message": "HexSOC real-time stream connected",
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

    async def _broadcast(self, payload: dict[str, Any]) -> None:
        disconnected: list[WebSocket] = []

        for websocket in list(self.active_connections):
            try:
                await websocket.send_json(payload)
            except Exception:
                disconnected.append(websocket)

        for websocket in disconnected:
            self.disconnect(websocket)


websocket_manager = WebSocketManager()
