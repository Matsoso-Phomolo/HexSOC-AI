"""Threat Intelligence Feed Integrator routes."""

from typing import Any

from fastapi import APIRouter, Body, Depends, Query
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.schemas.threat_ioc import (
    FeedNormalizeRequest,
    IOCCorrelateRequest,
    IOCCorrelationResponse,
    IOCLiveCorrelationResponse,
    IOCSearchResponse,
    ThreatIntelSyncStatus,
    ThreatIOCBulkCreate,
    ThreatIOCCreate,
    ThreatIOCIngestResponse,
    ThreatIOCRead,
)
from app.services.auth_service import require_role
from app.services.ioc_correlation_engine import correlate_indicators
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


@router.get("/search", response_model=IOCSearchResponse, summary="Search stored IOCs")
def search_iocs(
    q: str = Query(min_length=1, max_length=200),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("viewer")),
) -> dict[str, Any]:
    """Search IOC values, normalized values, sources, and tags with a bounded result set."""
    query_text = q.strip().lower()
    pattern = f"%{query_text}%"
    indicators = (
        db.query(models.ThreatIOC)
        .filter(
            models.ThreatIOC.is_active.is_(True),
            or_(
                models.ThreatIOC.value.ilike(pattern),
                models.ThreatIOC.normalized_value.ilike(pattern),
                models.ThreatIOC.source.ilike(pattern),
                models.ThreatIOC.classification.ilike(pattern),
            ),
        )
        .order_by(models.ThreatIOC.risk_score.desc(), models.ThreatIOC.id.desc())
        .limit(limit)
        .all()
    )
    return {"query": q, "total": len(indicators), "indicators": indicators}


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


@router.post(
    "/correlate",
    response_model=IOCCorrelationResponse | IOCLiveCorrelationResponse,
    summary="Correlate active IOCs or supplied indicators",
)
async def correlate_threat_iocs(
    payload: IOCCorrelateRequest | None = Body(default=None),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("analyst")),
) -> dict[str, Any]:
    """Create IOC relationships or correlate supplied raw indicators against stored IOCs."""
    if payload and payload.indicators:
        result = correlate_indicators(db, payload.indicators)
        await websocket_manager.broadcast_activity({"type": "threat_ioc_lookup_completed", "payload": {"matches_found": result["matches_found"]}})
        return result

    result = correlate_iocs(db)
    await websocket_manager.broadcast_activity({"type": "threat_ioc_correlated", "payload": result})
    await websocket_manager.broadcast_activity({"type": "graph_updated"})
    return result


@router.get("/sync-status", response_model=ThreatIntelSyncStatus, summary="Threat intel sync status")
def sync_status(
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("viewer")),
) -> dict[str, Any]:
    """Return operational counts for the local IOC intelligence lifecycle."""
    active_iocs = db.query(models.ThreatIOC).filter(models.ThreatIOC.is_active.is_(True)).count()
    expired_iocs = db.query(models.ThreatIOC).filter(models.ThreatIOC.is_active.is_(False)).count()
    link_count = db.query(models.ThreatIOCLink).count()
    source_count = db.query(func.count(func.distinct(models.ThreatIOC.source))).scalar() or 0
    top_sources = (
        db.query(models.ThreatIOC.source, func.count(models.ThreatIOC.id).label("count"))
        .group_by(models.ThreatIOC.source)
        .order_by(func.count(models.ThreatIOC.id).desc())
        .limit(10)
        .all()
    )
    return {
        "active_iocs": active_iocs,
        "expired_iocs": expired_iocs,
        "source_count": source_count,
        "link_count": link_count,
        "top_sources": [{"source": source, "count": count} for source, count in top_sources],
    }
