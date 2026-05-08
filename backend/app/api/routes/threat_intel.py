"""Threat intelligence enrichment endpoints."""

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.services.threat_intel_service import enrich_security_context
from app.services.websocket_manager import serialize_activity, websocket_manager

router = APIRouter()


@router.post("/enrich", summary="Run threat intelligence enrichment")
async def enrich_threat_intel(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Enrich stored security events and alerts with threat intelligence."""
    result = enrich_security_context(db)
    activities = result.pop("activities", [])

    for activity in activities:
        await websocket_manager.broadcast_activity(
            {"type": "activity_created", "activity": serialize_activity(activity)}
        )

    return result
