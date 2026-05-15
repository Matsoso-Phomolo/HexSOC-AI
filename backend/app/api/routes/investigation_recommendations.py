"""Investigation recommendation endpoints for deterministic SOC guidance."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.services.attack_chain_persistence_service import serialize_attack_chain, serialize_campaign
from app.services.auth_service import require_role
from app.services.investigation_recommendation_engine import (
    recommend_for_attack_chain,
    recommend_for_campaign,
    recommend_for_context,
)

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/recommendations/attack-chain/{chain_id}", summary="Recommend investigation actions for an attack chain")
def get_attack_chain_recommendations(
    chain_id: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("viewer", "analyst")),
) -> dict[str, Any]:
    """Return deterministic SOC recommendations for one persisted attack chain."""
    try:
        chain = _load_chain(db, chain_id)
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Failed to load attack chain %s for recommendations: %s", chain_id, exc)
        raise HTTPException(status_code=503, detail="Attack-chain recommendation storage unavailable") from exc
    if not chain:
        raise HTTPException(status_code=404, detail="Attack chain not found")
    return recommend_for_attack_chain(serialize_attack_chain(chain))


@router.get("/recommendations/campaign/{campaign_id}", summary="Recommend investigation actions for a campaign")
def get_campaign_recommendations(
    campaign_id: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("viewer", "analyst")),
) -> dict[str, Any]:
    """Return deterministic SOC recommendations for one persisted campaign cluster."""
    try:
        campaign = _load_campaign(db, campaign_id)
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Failed to load campaign %s for recommendations: %s", campaign_id, exc)
        raise HTTPException(status_code=503, detail="Campaign recommendation storage unavailable") from exc
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign cluster not found")
    return recommend_for_campaign(serialize_campaign(campaign))


@router.post("/recommendations/context", summary="Recommend investigation actions for supplied context")
def get_context_recommendations(
    payload: dict[str, Any] = Body(...),
    max_context_items: int = Query(50, ge=1, le=200),
    _: models.User = Depends(require_role("viewer", "analyst")),
) -> dict[str, Any]:
    """Return deterministic recommendations from bounded caller-supplied context."""
    entity_type = str(payload.get("entity_type") or "context")
    entity_id = str(payload.get("entity_id") or "ad_hoc")
    context = payload.get("context") or payload.get("payload") or {}
    if not isinstance(context, dict):
        raise HTTPException(status_code=400, detail="context must be an object")
    bounded_context = _bound_context(context, max_context_items)
    return recommend_for_context(entity_type, entity_id, bounded_context)


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


def _load_campaign(db: Session, campaign_id: str) -> models.CampaignCluster | None:
    if campaign_id.isdigit():
        return db.query(models.CampaignCluster).filter(models.CampaignCluster.id == int(campaign_id)).first()
    return (
        db.query(models.CampaignCluster)
        .filter(
            (models.CampaignCluster.stable_fingerprint == campaign_id)
            | (models.CampaignCluster.campaign_key == campaign_id)
        )
        .first()
    )


def _bound_context(context: dict[str, Any], max_items: int) -> dict[str, Any]:
    bounded: dict[str, Any] = {}
    for key, value in context.items():
        if isinstance(value, list):
            bounded[key] = value[:max_items]
        elif isinstance(value, dict):
            bounded[key] = dict(list(value.items())[:max_items])
        else:
            bounded[key] = value
    return bounded
