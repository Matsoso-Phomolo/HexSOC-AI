"""AI Analyst Copilot endpoints."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.services.activity_service import add_activity
from app.services.ai_copilot_service import (
    generate_attack_chain_summary,
    summarize_alert,
    summarize_incident,
)
from app.services.websocket_manager import serialize_activity, websocket_manager

router = APIRouter()


@router.get("/alert/{alert_id}", summary="Analyze alert with AI copilot")
async def analyze_alert(alert_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Return deterministic SOC analyst guidance for an alert."""
    alert = db.get(models.Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    result = summarize_alert(alert)
    activity = add_activity(
        db,
        action="copilot_alert_analysis",
        entity_type="alert",
        entity_id=alert.id,
        message=f"AI copilot analyzed alert: {alert.title}",
        severity=alert.severity or "info",
    )
    db.commit()
    db.refresh(activity)
    await _broadcast_completion(activity, {"target_type": "alert", "target_id": alert.id})
    return result


@router.get("/incident/{incident_id}", summary="Analyze incident with AI copilot")
async def analyze_incident(incident_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Return deterministic SOC analyst guidance for an incident."""
    incident = db.get(models.Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    result = summarize_incident(incident)
    activity = add_activity(
        db,
        action="copilot_incident_analysis",
        entity_type="incident",
        entity_id=incident.id,
        message=f"AI copilot analyzed incident: {incident.title}",
        severity=incident.severity or "info",
    )
    db.commit()
    db.refresh(activity)
    await _broadcast_completion(activity, {"target_type": "incident", "target_id": incident.id})
    return result


@router.post("/attack-chain-summary", summary="Analyze attack chain with AI copilot")
async def analyze_attack_chain(chain: dict[str, Any], db: Session = Depends(get_db)) -> dict[str, Any]:
    """Return deterministic SOC analyst guidance for an attack chain."""
    result = generate_attack_chain_summary(chain)
    source_ip = chain.get("source_ip", "unknown")
    activity = add_activity(
        db,
        action="copilot_chain_analysis",
        entity_type="attack_chain",
        entity_id=None,
        message=f"AI copilot analyzed attack chain for {source_ip}.",
        severity="info",
    )
    db.commit()
    db.refresh(activity)
    await _broadcast_completion(activity, {"target_type": "attack_chain", "source_ip": source_ip})
    return result


async def _broadcast_completion(activity: models.ActivityLog, payload: dict[str, Any]) -> None:
    await websocket_manager.broadcast_activity(
        {"type": "activity_created", "activity": serialize_activity(activity)}
    )
    await websocket_manager.broadcast_activity(
        {
            "type": "copilot_analysis_completed",
            **payload,
        }
    )
