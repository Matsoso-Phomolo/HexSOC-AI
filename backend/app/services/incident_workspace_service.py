"""Build bounded investigation workspace context for escalated incidents."""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy.orm import Session

from app.db import models
from app.services.attack_chain_persistence_service import (
    serialize_attack_chain,
    serialize_attack_chain_step,
    serialize_campaign,
)
from app.services.investigation_recommendation_engine import recommend_for_attack_chain, recommend_for_campaign, recommend_for_context


ESCALATION_MARKER_RE = re.compile(r"\[hexsoc-escalation:(attack_chain|campaign|[^:\]]+):([^\]]+)\]")
MAX_WORKSPACE_ITEMS = 25


def build_incident_workspace(db: Session, incident: models.Incident) -> dict[str, Any]:
    """Return a bounded investigation workspace for an incident."""
    marker = parse_escalation_marker(incident.description or "")
    linked_chain = None
    linked_campaign = None
    timeline_steps: list[dict[str, Any]] = []
    recommendations: dict[str, Any] = {}

    if marker and marker["entity_type"] == "attack_chain":
        chain = _load_attack_chain(db, marker["entity_id"])
        if chain:
            linked_chain = serialize_attack_chain(chain)
            timeline_steps = _timeline_steps(db, chain.id)
            recommendations = recommend_for_attack_chain(linked_chain)
    elif marker and marker["entity_type"] == "campaign":
        campaign = _load_campaign(db, marker["entity_id"])
        if campaign:
            linked_campaign = serialize_campaign(campaign)
            recommendations = recommend_for_campaign(linked_campaign)

    if not recommendations:
        recommendations = recommend_for_context(
            "incident",
            str(incident.id),
            {
                "risk_score": 75 if incident.severity == "critical" else 50 if incident.severity == "high" else 25,
                "severity": incident.severity,
                "classification": incident.priority or incident.severity,
                "summary": incident.summary,
            },
        )

    notes = _case_notes(db, incident.id)
    evidence = _case_evidence(db, incident.id)

    return {
        "incident": _incident_payload(incident),
        "linked_attack_chain": linked_chain,
        "linked_campaign": linked_campaign,
        "timeline_preview": timeline_steps,
        "recommendations": recommendations,
        "evidence_checklist": _evidence_checklist(recommendations),
        "case_notes": notes,
        "case_evidence": evidence,
        "summary": {
            "linked_entity_type": marker["entity_type"] if marker else None,
            "linked_entity_id": marker["entity_id"] if marker else None,
            "timeline_steps": len(timeline_steps),
            "case_notes": len(notes),
            "case_evidence": len(evidence),
            "workspace_status": "linked" if marker else "unlinked",
        },
    }


def parse_escalation_marker(text: str) -> dict[str, str] | None:
    """Extract the first HexSOC escalation marker from incident text."""
    match = ESCALATION_MARKER_RE.search(text or "")
    if not match:
        return None
    return {"entity_type": match.group(1), "entity_id": match.group(2)}


def _load_attack_chain(db: Session, chain_id: str) -> models.AttackChain | None:
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


def _timeline_steps(db: Session, chain_id: int) -> list[dict[str, Any]]:
    steps = (
        db.query(models.AttackChainStep)
        .filter(models.AttackChainStep.attack_chain_id == chain_id)
        .order_by(models.AttackChainStep.step_index.asc(), models.AttackChainStep.timestamp.asc().nullslast())
        .limit(MAX_WORKSPACE_ITEMS)
        .all()
    )
    return [serialize_attack_chain_step(step) for step in steps]


def _case_notes(db: Session, incident_id: int) -> list[dict[str, Any]]:
    notes = (
        db.query(models.CaseNote)
        .filter(models.CaseNote.incident_id == incident_id)
        .order_by(models.CaseNote.id.desc())
        .limit(MAX_WORKSPACE_ITEMS)
        .all()
    )
    return [
        {
            "id": note.id,
            "author": note.author,
            "note_type": note.note_type,
            "content": note.content,
            "created_at": _iso(note.created_at),
        }
        for note in notes
    ]


def _case_evidence(db: Session, incident_id: int) -> list[dict[str, Any]]:
    evidence = (
        db.query(models.CaseEvidence)
        .filter(models.CaseEvidence.incident_id == incident_id)
        .order_by(models.CaseEvidence.id.desc())
        .limit(MAX_WORKSPACE_ITEMS)
        .all()
    )
    return [
        {
            "id": item.id,
            "evidence_type": item.evidence_type,
            "title": item.title,
            "description": item.description,
            "source": item.source,
            "reference_id": item.reference_id,
            "created_at": _iso(item.created_at),
        }
        for item in evidence
    ]


def _evidence_checklist(recommendations: dict[str, Any]) -> list[dict[str, Any]]:
    items = recommendations.get("evidence_to_collect") or []
    return [
        {
            "title": str(item)[:180],
            "evidence_type": "investigation",
            "source": "HexSOC AI recommendation",
            "required": True,
        }
        for item in items[:MAX_WORKSPACE_ITEMS]
    ]


def _incident_payload(incident: models.Incident) -> dict[str, Any]:
    return {
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "priority": incident.priority,
        "case_status": incident.case_status,
        "assigned_to": incident.assigned_to,
        "escalation_level": incident.escalation_level,
        "summary": incident.summary,
        "description": incident.description,
        "created_at": _iso(incident.created_at),
        "updated_at": _iso(incident.updated_at),
    }


def _iso(value: Any) -> str | None:
    return value.isoformat() if value else None
