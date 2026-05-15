"""Investigation session workflows for attack chains and campaign clusters."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.db import models


def create_from_attack_chain(
    db: Session,
    chain: models.AttackChain,
    *,
    assigned_to: str | None = None,
) -> models.InvestigationSession:
    """Create an investigation session for a persistent attack chain."""
    session = models.InvestigationSession(
        attack_chain_id=chain.id,
        title=f"Investigation: {chain.title}",
        assigned_to=assigned_to,
        status="open",
        priority=_priority_from_risk(chain.risk_score),
        analyst_notes=chain.summary,
        evidence_refs={"attack_chain_id": chain.id, "stable_fingerprint": chain.stable_fingerprint},
    )
    db.add(session)
    return session


def update_session(session: models.InvestigationSession, payload: dict[str, Any]) -> models.InvestigationSession:
    """Apply bounded analyst-controlled investigation updates."""
    for field in ["assigned_to", "status", "priority", "analyst_notes"]:
        if field in payload:
            setattr(session, field, payload[field])
    if "evidence_refs" in payload and isinstance(payload["evidence_refs"], (dict, list)):
        session.evidence_refs = payload["evidence_refs"]
    return session


def serialize_session(session: models.InvestigationSession) -> dict[str, Any]:
    """Return an API-safe investigation session summary."""
    return {
        "id": session.id,
        "attack_chain_id": session.attack_chain_id,
        "campaign_cluster_id": session.campaign_cluster_id,
        "title": session.title,
        "assigned_to": session.assigned_to,
        "status": session.status,
        "priority": session.priority,
        "analyst_notes": session.analyst_notes,
        "evidence_refs": session.evidence_refs,
        "created_at": session.created_at.isoformat() if session.created_at else None,
        "updated_at": session.updated_at.isoformat() if session.updated_at else None,
    }


def _priority_from_risk(score: int | None) -> str:
    value = score or 0
    if value >= 75:
        return "critical"
    if value >= 50:
        return "high"
    if value >= 25:
        return "medium"
    return "low"
