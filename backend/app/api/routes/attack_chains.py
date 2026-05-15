"""Persistent attack-chain and investigation session API endpoints."""

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
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


@router.post("/attack-chains/rebuild", summary="Rebuild and persist attack-chain intelligence")
async def rebuild_attack_chain_intelligence(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> dict[str, Any]:
    """Compute bounded candidates and persist them as stable investigation objects."""
    computed = build_attack_chains(db, limit=limit)
    persisted = persist_attack_chains(db, computed)
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
    db.commit()
    db.refresh(activity)

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
    chains = (
        db.query(models.AttackChain)
        .order_by(models.AttackChain.risk_score.desc(), models.AttackChain.last_seen.desc().nullslast(), models.AttackChain.id.desc())
        .limit(limit)
        .all()
    )
    return {
        "total": len(chains),
        "limit": limit,
        "chains": [serialize_attack_chain(chain) for chain in chains],
    }


@router.get("/attack-chains/{chain_id}", summary="Get persisted attack chain")
def retrieve_attack_chain(
    chain_id: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("viewer", "analyst")),
) -> dict[str, Any]:
    """Return one stable attack chain by database ID or fingerprint."""
    chain = _load_chain(db, chain_id)
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
    chain = _load_chain(db, chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Attack chain not found")
    steps = (
        db.query(models.AttackChainStep)
        .filter(models.AttackChainStep.attack_chain_id == chain.id)
        .order_by(models.AttackChainStep.step_index.asc(), models.AttackChainStep.timestamp.asc().nullslast())
        .limit(limit)
        .all()
    )
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
    campaigns = (
        db.query(models.CampaignCluster)
        .order_by(models.CampaignCluster.risk_score.desc(), models.CampaignCluster.last_seen.desc().nullslast(), models.CampaignCluster.id.desc())
        .limit(limit)
        .all()
    )
    return {
        "total": len(campaigns),
        "limit": limit,
        "campaigns": [serialize_campaign(campaign) for campaign in campaigns],
    }


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
