"""Persistent attack-chain and investigation session API endpoints."""

import logging
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.db.database import ensure_attack_chain_schema
from app.services.activity_service import add_activity
from app.services.attack_chain_engine import build_attack_chains
from app.services.attack_chain_persistence_service import (
    persist_attack_chains,
    serialize_attack_chain,
    serialize_attack_chain_step,
    serialize_campaign,
)
from app.services.auth_service import require_role
from app.services.investigation_session_service import create_from_attack_chain, serialize_session, update_session
from app.services.websocket_manager import serialize_activity, websocket_manager

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/attack-chains/rebuild", summary="Rebuild and persist attack-chain intelligence")
async def rebuild_attack_chain_intelligence(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> dict[str, Any]:
    """Compute bounded candidates and persist them as stable investigation objects."""
    try:
        computed = build_attack_chains(db, limit=limit)
        persisted = persist_attack_chains(db, computed)
    except Exception as exc:
        db.rollback()
        logger.exception("Attack-chain rebuild failed before persistence: %s", exc)
        try:
            ensure_attack_chain_schema()
        except Exception as schema_exc:
            logger.exception("On-demand attack-chain schema sync failed after rebuild error: %s", schema_exc)
        fallback = _empty_attack_chain_response(limit=limit, error="attack_chain_rebuild_failed")
        return {
            **fallback,
            "chains_found": 0,
            "persisted": 0,
            "highest_risk_score": 0,
            "critical_chains": 0,
            "high_chains": 0,
        }

    critical_count = sum(1 for chain in persisted if chain["classification"] == "critical")
    high_count = sum(1 for chain in persisted if chain["classification"] == "high")
    highest_risk = max((chain["risk_score"] for chain in persisted), default=0)

    activity = add_activity(
        db,
        action="attack_chains_rebuilt",
        entity_type="attack_chain",
        entity_id=None,
        message=f"Attack-chain rebuild persisted {len(persisted)} stable chain candidates.",
        severity="info" if critical_count == 0 else "high",
        actor_username=user.username,
        actor_role=user.role,
    )
    try:
        db.commit()
        db.refresh(activity)
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Attack-chain rebuild commit failed: %s", exc)
        fallback = _empty_attack_chain_response(limit=limit, error="attack_chain_commit_failed")
        return {
            **fallback,
            "chains_found": 0,
            "persisted": 0,
            "highest_risk_score": 0,
            "critical_chains": 0,
            "high_chains": 0,
        }

    result = {
        "chains_found": len(persisted),
        "persisted": len(persisted),
        "highest_risk_score": highest_risk,
        "critical_chains": critical_count,
        "high_chains": high_count,
        "chains": persisted,
    }

    await websocket_manager.broadcast_activity(
        {"type": "activity_created", "activity": serialize_activity(activity)}
    )
    await websocket_manager.broadcast_event(
        "attack_chains_rebuilt",
        {"chains_found": result["chains_found"], "highest_risk_score": result["highest_risk_score"]},
    )
    await websocket_manager.broadcast_event("graph_updated")
    await websocket_manager.broadcast_dashboard_metrics(db)
    return result


@router.get("/attack-chains", summary="List persisted attack chains")
def list_attack_chains(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("viewer", "analyst")),
) -> dict[str, Any]:
    """Return stable persisted attack chains sorted by risk and recency."""
    try:
        chains = (
            db.query(models.AttackChain)
            .order_by(models.AttackChain.risk_score.desc(), models.AttackChain.last_seen.desc().nullslast(), models.AttackChain.id.desc())
            .limit(limit)
            .all()
        )
        serialized = [serialize_attack_chain(chain) for chain in chains]
        logger.debug("Loaded %s persisted attack chains", len(serialized))
        return {
            "total": len(serialized),
            "limit": limit,
            "chains": serialized,
            "summary": {"source": "persisted", "error": None},
        }
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Failed to load persisted attack chains; returning safe fallback: %s", exc)
        try:
            ensure_attack_chain_schema()
            chains = (
                db.query(models.AttackChain)
                .order_by(models.AttackChain.risk_score.desc(), models.AttackChain.last_seen.desc().nullslast(), models.AttackChain.id.desc())
                .limit(limit)
                .all()
            )
            serialized = [serialize_attack_chain(chain) for chain in chains]
            return {"total": len(serialized), "limit": limit, "chains": serialized, "summary": {"source": "persisted_retry", "error": None}}
        except Exception as retry_exc:
            db.rollback()
            logger.exception("Attack-chain load retry failed; returning fallback: %s", retry_exc)
    except Exception as exc:
        logger.exception("Failed to serialize persisted attack chains; returning safe fallback: %s", exc)
    return _empty_attack_chain_response(limit=limit, error="attack_chain_load_failed")


@router.get("/attack-chains/{chain_id}", summary="Get persisted attack chain")
def retrieve_attack_chain(
    chain_id: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("viewer", "analyst")),
) -> dict[str, Any]:
    """Return one stable attack chain by database ID or fingerprint."""
    try:
        chain = _load_chain(db, chain_id)
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Failed to load attack chain %s: %s", chain_id, exc)
        raise HTTPException(status_code=503, detail="Attack chain storage unavailable") from exc
    if not chain:
        raise HTTPException(status_code=404, detail="Attack chain not found")
    return serialize_attack_chain(chain)


@router.get("/attack-chains/{chain_id}/timeline", summary="Get persisted attack-chain timeline")
def retrieve_attack_chain_timeline(
    chain_id: str,
    limit: int = Query(100, ge=1, le=200),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("viewer", "analyst")),
) -> dict[str, Any]:
    """Return persisted ordered timeline steps for a stable chain."""
    try:
        chain = _load_chain(db, chain_id)
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Failed to load attack chain %s timeline chain record: %s", chain_id, exc)
        return _empty_timeline_response(chain_id, error="attack_chain_storage_unavailable")
    if not chain:
        logger.warning("Timeline requested for missing attack chain %s; returning bounded fallback", chain_id)
        return _empty_timeline_response(chain_id, error="attack_chain_not_found")
    try:
        steps = (
            db.query(models.AttackChainStep)
            .filter(models.AttackChainStep.attack_chain_id == chain.id)
            .order_by(models.AttackChainStep.step_index.asc(), models.AttackChainStep.timestamp.asc().nullslast())
            .limit(limit)
            .all()
        )
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Failed to load attack chain %s timeline steps: %s", chain_id, exc)
        steps = []
    return {
        "chain_id": str(chain.id),
        "stable_fingerprint": chain.stable_fingerprint,
        "timeline": serialize_attack_chain(chain)["timeline"],
        "steps": [serialize_attack_chain_step(step) for step in steps],
    }


@router.patch("/attack-chains/{chain_id}/status", summary="Update attack-chain status")
async def update_attack_chain_status(
    chain_id: str,
    payload: dict[str, str] = Body(...),
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> dict[str, Any]:
    """Update analyst workflow status for one persistent attack chain."""
    chain = _load_chain(db, chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Attack chain not found")
    next_status = payload.get("status")
    if next_status not in {"open", "investigating", "contained", "resolved", "false_positive"}:
        raise HTTPException(status_code=400, detail="Invalid attack-chain status")
    chain.status = next_status
    activity = add_activity(
        db,
        action="attack_chain_status_changed",
        entity_type="attack_chain",
        entity_id=chain.id,
        message=f"Attack chain {chain.id} status changed to {next_status}.",
        severity="info",
        actor_username=user.username,
        actor_role=user.role,
    )
    db.commit()
    db.refresh(chain)
    db.refresh(activity)
    await websocket_manager.broadcast_activity({"type": "activity_created", "activity": serialize_activity(activity)})
    await websocket_manager.broadcast_event("attack_chain_updated", {"chain_id": chain.id, "status": next_status})
    return serialize_attack_chain(chain)


@router.get("/campaigns", summary="List persisted campaign clusters")
def list_campaigns(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("viewer", "analyst")),
) -> dict[str, Any]:
    """Return stable lightweight campaign summaries."""
    try:
        campaigns = (
            db.query(models.CampaignCluster)
            .order_by(models.CampaignCluster.risk_score.desc(), models.CampaignCluster.last_seen.desc().nullslast(), models.CampaignCluster.id.desc())
            .limit(limit)
            .all()
        )
        serialized = [serialize_campaign(campaign) for campaign in campaigns]
        return {
            "total": len(serialized),
            "limit": limit,
            "campaigns": serialized,
            "summary": {"source": "persisted", "error": None},
        }
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Failed to load campaign clusters; returning safe fallback: %s", exc)
        try:
            ensure_attack_chain_schema()
            campaigns = (
                db.query(models.CampaignCluster)
                .order_by(models.CampaignCluster.risk_score.desc(), models.CampaignCluster.last_seen.desc().nullslast(), models.CampaignCluster.id.desc())
                .limit(limit)
                .all()
            )
            serialized = [serialize_campaign(campaign) for campaign in campaigns]
            return {"total": len(serialized), "limit": limit, "campaigns": serialized, "summary": {"source": "persisted_retry", "error": None}}
        except Exception as retry_exc:
            db.rollback()
            logger.exception("Campaign cluster load retry failed; returning fallback: %s", retry_exc)
    except Exception as exc:
        logger.exception("Failed to serialize campaign clusters; returning safe fallback: %s", exc)
    return {"total": 0, "limit": limit, "campaigns": [], "summary": {"source": "fallback", "error": "campaign_load_failed"}}


@router.post("/investigations/from-attack-chain/{chain_id}", summary="Create investigation from attack chain")
async def create_investigation_from_chain(
    chain_id: str,
    payload: dict[str, Any] | None = Body(default=None),
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> dict[str, Any]:
    """Open an investigation session for a persistent attack chain."""
    chain = _load_chain(db, chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Attack chain not found")
    payload = payload or {}
    session = create_from_attack_chain(db, chain, assigned_to=payload.get("assigned_to") or user.username)
    activity = add_activity(
        db,
        action="investigation_session_created",
        entity_type="investigation_session",
        entity_id=None,
        message=f"Investigation session opened for attack chain {chain.id}.",
        severity="info",
        actor_username=user.username,
        actor_role=user.role,
    )
    db.commit()
    db.refresh(session)
    activity.entity_id = session.id
    db.commit()
    db.refresh(activity)
    await websocket_manager.broadcast_activity({"type": "activity_created", "activity": serialize_activity(activity)})
    await websocket_manager.broadcast_event("investigation_session_created", {"session_id": session.id, "attack_chain_id": chain.id})
    return serialize_session(session)


@router.get("/investigations", summary="List investigation sessions")
def list_investigations(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("viewer", "analyst")),
) -> dict[str, Any]:
    """Return bounded investigation session summaries."""
    sessions = (
        db.query(models.InvestigationSession)
        .order_by(models.InvestigationSession.updated_at.desc().nullslast(), models.InvestigationSession.created_at.desc(), models.InvestigationSession.id.desc())
        .limit(limit)
        .all()
    )
    return {"total": len(sessions), "limit": limit, "sessions": [serialize_session(session) for session in sessions]}


@router.patch("/investigations/{session_id}", summary="Update investigation session")
async def update_investigation(
    session_id: int,
    payload: dict[str, Any] = Body(...),
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> dict[str, Any]:
    """Update notes, status, priority, or assignment on an investigation session."""
    session = db.query(models.InvestigationSession).filter(models.InvestigationSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Investigation session not found")
    update_session(session, payload)
    activity = add_activity(
        db,
        action="investigation_session_updated",
        entity_type="investigation_session",
        entity_id=session.id,
        message=f"Investigation session {session.id} updated.",
        severity="info",
        actor_username=user.username,
        actor_role=user.role,
    )
    db.commit()
    db.refresh(session)
    db.refresh(activity)
    await websocket_manager.broadcast_activity({"type": "activity_created", "activity": serialize_activity(activity)})
    await websocket_manager.broadcast_event("investigation_session_updated", {"session_id": session.id})
    return serialize_session(session)


def _load_chain(db: Session, chain_id: str) -> models.AttackChain | None:
    if chain_id.isdigit():
        return db.query(models.AttackChain).filter(models.AttackChain.id == int(chain_id)).first()
    return (
        db.query(models.AttackChain)
        .filter(
            (models.AttackChain.stable_fingerprint == chain_id)
            | (models.AttackChain.chain_key == chain_id)
        )
        .first()
    )


def _empty_attack_chain_response(*, limit: int, error: str | None = None) -> dict[str, Any]:
    return {
        "total": 0,
        "limit": limit,
        "chains": [],
        "summary": {
            "source": "fallback",
            "error": error,
            "message": "Attack-chain storage is unavailable or no persisted chains exist yet.",
        },
    }


def _empty_timeline_response(chain_id: str, *, error: str | None = None) -> dict[str, Any]:
    return {
        "chain_id": chain_id,
        "timeline": {
            "total_steps": 0,
            "first_seen": None,
            "last_seen": None,
            "stages": [],
            "highest_severity": "info",
            "summary": "No persisted timeline steps are available.",
        },
        "steps": [],
        "summary": {"source": "fallback", "error": error},
    }
