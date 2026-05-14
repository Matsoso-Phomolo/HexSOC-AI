"""Threat Intelligence Feed Integrator routes."""

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.schemas.threat_ioc import (
    FeedNormalizeRequest,
    IOCCorrelationResponse,
    ThreatIOCBulkCreate,
    ThreatIOCCreate,
    ThreatIOCIngestResponse,
    ThreatIOCRead,
)
from app.services.auth_service import require_role
from app.services.threat_intel_feed_service import correlate_iocs, ingest_iocs, normalize_and_ingest_feed
from app.services.websocket_manager import websocket_manager

router = APIRouter()


@router.get("/iocs", response_model=list[ThreatIOCRead], summary="List normalized IOCs")
def list_iocs(
    ioc_type: str | None = Query(default=None),
    source: str | None = Query(default=None),
    active_only: bool = Query(default=True),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("viewer")),
) -> list[models.ThreatIOC]:
    """List normalized threat indicators with bounded pagination."""
    query = db.query(models.ThreatIOC).order_by(models.ThreatIOC.risk_score.desc(), models.ThreatIOC.id.desc())
    if ioc_type:
        query = query.filter(models.ThreatIOC.ioc_type == ioc_type.lower().strip())
    if source:
        query = query.filter(models.ThreatIOC.source == source.lower().strip())
    if active_only:
        query = query.filter(models.ThreatIOC.is_active.is_(True))
    return query.limit(limit).all()


@router.post("/iocs", response_model=ThreatIOCIngestResponse, summary="Ingest one IOC")
async def create_ioc(
    payload: ThreatIOCCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> dict[str, Any]:
    """Create or update a single normalized IOC."""
    result = ingest_iocs(db, [payload], actor_username=user.username, actor_role=user.role)
    await websocket_manager.broadcast_activity({"type": "threat_ioc_ingested", "payload": {"created": result["created"], "updated": result["updated"]}})
    return {**result, "source": payload.source}


@router.post("/iocs/bulk", response_model=ThreatIOCIngestResponse, summary="Bulk ingest IOCs")
async def bulk_create_iocs(
    payload: ThreatIOCBulkCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> dict[str, Any]:
    """Create or update a batch of normalized IOCs."""
    indicators = [indicator.model_copy(update={"source": indicator.source or payload.source}) for indicator in payload.indicators]
    result = ingest_iocs(db, indicators, actor_username=user.username, actor_role=user.role)
    await websocket_manager.broadcast_activity({"type": "threat_ioc_ingested", "payload": {"created": result["created"], "updated": result["updated"]}})
    return {**result, "source": payload.source}


@router.post("/feeds/normalize", response_model=ThreatIOCIngestResponse, summary="Normalize and ingest feed payload")
async def normalize_feed(
    payload: FeedNormalizeRequest,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> dict[str, Any]:
    """Normalize a provider feed payload through the adapter layer and ingest IOCs."""
    result = normalize_and_ingest_feed(
        db,
        payload.source,
        payload.payload,
        default_ttl_days=payload.default_ttl_days,
        actor_username=user.username,
        actor_role=user.role,
    )
    await websocket_manager.broadcast_activity({"type": "threat_ioc_ingested", "payload": {"created": result["created"], "updated": result["updated"]}})
    return {**result, "source": payload.source}


@router.post("/correlate", response_model=IOCCorrelationResponse, summary="Correlate active IOCs with SOC entities")
async def correlate_threat_iocs(
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("analyst")),
) -> dict[str, int]:
    """Create IOC relationships to matching alerts, events, and assets."""
    result = correlate_iocs(db)
    await websocket_manager.broadcast_activity({"type": "threat_ioc_correlated", "payload": result})
    await websocket_manager.broadcast_activity({"type": "graph_updated"})
    return result
