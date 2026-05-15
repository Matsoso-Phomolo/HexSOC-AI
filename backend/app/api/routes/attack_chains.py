"""Attack-chain intelligence API endpoints."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.services.activity_service import add_activity
from app.services.attack_chain_engine import build_attack_chains, get_attack_chain, rebuild_attack_chains
from app.services.campaign_cluster_engine import build_campaign_clusters
from app.services.auth_service import require_role
from app.services.websocket_manager import serialize_activity, websocket_manager

router = APIRouter()


@router.post("/attack-chains/rebuild", summary="Rebuild computed attack-chain intelligence")
async def rebuild_attack_chain_intelligence(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> dict[str, Any]:
    """Run bounded attack-chain reconstruction over stored SOC records."""
    result = rebuild_attack_chains(db, limit=limit)
    activity = add_activity(
        db,
        action="attack_chains_rebuilt",
        entity_type="attack_chain",
        entity_id=None,
        message=f"Attack-chain rebuild completed with {result['chains_found']} chain candidates.",
        severity="info" if result["critical_chains"] == 0 else "high",
        actor_username=user.username,
        actor_role=user.role,
    )
    db.commit()
    db.refresh(activity)

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


@router.get("/attack-chains", summary="List computed attack chains")
def list_attack_chains(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("viewer", "analyst")),
) -> dict[str, Any]:
    """Return bounded attack-chain candidates sorted by risk."""
    chains = build_attack_chains(db, limit=limit)
    return {
        "total": len(chains),
        "limit": limit,
        "chains": chains,
    }


@router.get("/attack-chains/{chain_id}", summary="Get one computed attack chain")
def retrieve_attack_chain(
    chain_id: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("viewer", "analyst")),
) -> dict[str, Any]:
    """Return one computed chain by deterministic chain ID."""
    chain = get_attack_chain(db, chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Attack chain not found")
    return chain


@router.get("/attack-chains/{chain_id}/timeline", summary="Get attack-chain timeline")
def retrieve_attack_chain_timeline(
    chain_id: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("viewer", "analyst")),
) -> dict[str, Any]:
    """Return compact replay-ready timeline steps for one chain."""
    chain = get_attack_chain(db, chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Attack chain not found")
    return {
        "chain_id": chain_id,
        "timeline": chain["timeline"],
        "steps": chain["timeline_steps"],
    }


@router.get("/campaigns", summary="List campaign cluster candidates")
def list_campaigns(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("viewer", "analyst")),
) -> dict[str, Any]:
    """Return lightweight campaign summaries derived from attack chains."""
    chains = build_attack_chains(db, limit=200)
    campaigns = build_campaign_clusters(chains, limit=limit)
    return {
        "total": len(campaigns),
        "limit": limit,
        "campaigns": campaigns,
    }
