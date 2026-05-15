"""Threat intelligence enrichment endpoints."""

from typing import Any

from fastapi import APIRouter, Body, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.schemas.threat_ioc import ThreatProviderEnrichRequest
from app.services.auth_service import require_role
from app.services.threat_intel_provider_orchestrator import enrich_indicators, provider_status
from app.services.threat_intel_service import enrich_security_context
from app.services.websocket_manager import serialize_activity, websocket_manager

router = APIRouter()


@router.post("/enrich", summary="Run threat intelligence enrichment")
async def enrich_threat_intel(
    payload: ThreatProviderEnrichRequest | None = Body(default=None),
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> dict[str, Any]:
    """Enrich supplied indicators or stored security events and alerts."""
    if payload and payload.indicators:
        return enrich_indicators(
            db,
            payload.indicators,
            providers=payload.providers,
            persist=payload.persist,
            actor_username=user.username,
            actor_role=user.role,
        )

    result = enrich_security_context(db)
    activities = result.pop("activities", [])

    for activity in activities:
        await websocket_manager.broadcast_activity(
            {"type": "activity_created", "activity": serialize_activity(activity)}
        )
    await websocket_manager.broadcast_activity({"type": "graph_updated"})

    return result


@router.get("/providers/status", summary="Threat intelligence provider status")
def threat_provider_status(
    _: models.User = Depends(require_role("viewer")),
) -> list[dict[str, Any]]:
    """Return provider readiness without exposing secrets."""
    return provider_status()
