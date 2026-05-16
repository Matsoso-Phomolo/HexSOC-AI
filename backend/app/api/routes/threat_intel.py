"""Threat intelligence enrichment endpoints."""

from typing import Any

from fastapi import APIRouter, Body, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.schemas.threat_ioc import AutoCorrelateRequest, AutoCorrelateResponse, ThreatProviderEnrichRequest
from app.security.permissions import Permission, require_permission
from app.services.automated_correlation_engine import auto_correlate_entity, correlation_summary, risk_hotspots
from app.services.threat_intel_service import enrich_security_context
from app.services.websocket_manager import serialize_activity, websocket_manager

try:
    from app.services.threat_intel_provider_orchestrator import enrich_indicators, provider_status
except ImportError:  # pragma: no cover - provider layer may be disabled in local builds.
    enrich_indicators = None
    provider_status = None

router = APIRouter()


@router.post("/enrich", summary="Run threat intelligence enrichment")
async def enrich_threat_intel(
    payload: ThreatProviderEnrichRequest | None = Body(default=None),
    db: Session = Depends(get_db),
    user: models.User = Depends(require_permission(Permission.THREAT_INTEL_RUN)),
) -> dict[str, Any]:
    """Enrich supplied indicators or stored security events and alerts."""
    if payload and payload.indicators:
        if not enrich_indicators:
            return {
                "total_received": len(payload.indicators),
                "enriched": 0,
                "skipped": len(payload.indicators),
                "provider_errors": [{"provider": "orchestrator", "error": "Provider orchestrator is not available"}],
                "results": [],
            }
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


@router.post("/auto-correlate", response_model=AutoCorrelateResponse, summary="Run automated IOC correlation")
async def auto_correlate_threat_intel(
    payload: AutoCorrelateRequest,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_permission(Permission.THREAT_INTEL_RUN)),
) -> dict[str, Any]:
    """Extract IOCs from one entity payload and correlate against local threat intelligence."""
    result = auto_correlate_entity(
        db,
        entity_type=payload.entity_type,
        entity_id=payload.entity_id,
        payload=payload.payload,
        use_providers=payload.use_providers,
        persist_relationships=payload.persist_relationships,
    )
    if result["relationships_created"]:
        await websocket_manager.broadcast_activity({"type": "threat_ioc_correlated", "payload": result})
        await websocket_manager.broadcast_activity({"type": "graph_updated"})
    return result


@router.get("/correlation-summary", summary="Threat intelligence correlation summary")
def get_correlation_summary(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_permission(Permission.THREAT_INTEL_READ)),
) -> dict[str, Any]:
    """Return bounded correlation summary for local IOC relationships."""
    return correlation_summary(db, limit=limit)


@router.get("/risk-hotspots", summary="Threat intelligence risk hotspots")
def get_risk_hotspots(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_permission(Permission.THREAT_INTEL_READ)),
) -> list[dict[str, Any]]:
    """Return highest-risk IOC/entity relationships."""
    return risk_hotspots(db, limit=limit)


@router.get("/providers/status", summary="Threat intelligence provider status")
def threat_provider_status(_: models.User = Depends(require_permission(Permission.THREAT_INTEL_READ))) -> list[dict[str, Any]]:
    """Return provider readiness without exposing secrets."""
    return provider_status() if provider_status else []
