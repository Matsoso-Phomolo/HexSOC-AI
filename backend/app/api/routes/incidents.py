from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.schemas.incident import IncidentCreate, IncidentRead, IncidentStatusUpdate
from app.services.activity_service import add_activity
from app.services.attack_chain_persistence_service import serialize_attack_chain, serialize_campaign
from app.services.auth_service import require_role
from app.services.incident_escalation_engine import escalate_attack_chain, escalate_campaign, escalate_context
from app.services.incident_workspace_service import build_incident_workspace
from app.services.investigation_recommendation_engine import (
    recommend_for_attack_chain,
    recommend_for_campaign,
    recommend_for_context,
)
from app.services.websocket_manager import serialize_activity, websocket_manager

router = APIRouter()


@router.post("/", response_model=IncidentRead, status_code=201, summary="Create incident")
async def create_incident(
    payload: IncidentCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> models.Incident:
    """Store an incident case for security response."""
    incident = models.Incident(**payload.dict())
    db.add(incident)
    db.flush()
    activity = add_activity(
        db,
        action="incident_created",
        entity_type="incident",
        entity_id=incident.id,
        message=f"Incident created: {incident.title}",
        severity=incident.severity,
    )
    db.commit()
    db.refresh(incident)
    db.refresh(activity)
    await websocket_manager.broadcast_activity(
        {"type": "activity_created", "activity": serialize_activity(activity)}
    )
    await websocket_manager.broadcast_event("incident_updated", {"incident_id": incident.id, "status": incident.status})
    await websocket_manager.broadcast_dashboard_metrics(db)
    return incident


@router.get("/", response_model=list[IncidentRead], summary="List incidents")
def list_incidents(db: Session = Depends(get_db)) -> list[models.Incident]:
    """Return stored incidents ordered by newest first."""
    return db.query(models.Incident).order_by(models.Incident.id.desc()).all()


@router.patch("/{incident_id}/status", response_model=IncidentRead, summary="Update incident status")
async def update_incident_status(
    incident_id: int,
    payload: IncidentStatusUpdate,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> models.Incident:
    """Update the lifecycle status for an incident."""
    incident = db.get(models.Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    previous_status = incident.status
    incident.status = payload.status
    activity = add_activity(
        db,
        action="incident_status_changed",
        entity_type="incident",
        entity_id=incident.id,
        message=f"Incident status changed from {previous_status} to {incident.status}",
        severity=incident.severity or "info",
    )
    db.commit()
    db.refresh(incident)
    db.refresh(activity)
    await websocket_manager.broadcast_alert(
        {
            "type": "incident_status_changed",
            "incident_id": incident.id,
            "status": incident.status,
        }
    )
    await websocket_manager.broadcast_activity(
        {"type": "activity_created", "activity": serialize_activity(activity)}
    )
    await websocket_manager.broadcast_event("incident_updated", {"incident_id": incident.id, "status": incident.status})
    await websocket_manager.broadcast_dashboard_metrics(db)
    return incident


@router.get("/{incident_id}/workspace", summary="Get incident investigation workspace")
def get_incident_workspace(
    incident_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("viewer", "analyst")),
) -> dict:
    """Return bounded linked investigation context for an incident."""
    incident = db.get(models.Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return build_incident_workspace(db, incident)


@router.post("/{incident_id}/workspace/evidence-checklist", summary="Create evidence checklist records")
async def create_workspace_evidence_checklist(
    incident_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> dict:
    """Create case evidence records from workspace recommendation checklist items."""
    incident = db.get(models.Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    workspace = build_incident_workspace(db, incident)
    created = 0
    existing_titles = {
        title
        for (title,) in db.query(models.CaseEvidence.title)
        .filter(models.CaseEvidence.incident_id == incident.id)
        .limit(500)
        .all()
    }
    for item in workspace.get("evidence_checklist", [])[:25]:
        title = item.get("title")
        if not title or title in existing_titles:
            continue
        db.add(
            models.CaseEvidence(
                incident_id=incident.id,
                evidence_type=item.get("evidence_type") or "investigation",
                title=title,
                description="Generated from HexSOC AI investigation workspace checklist.",
                source=item.get("source") or "HexSOC AI recommendation",
                reference_id=f"workspace:{incident.id}",
            )
        )
        created += 1
    activity = add_activity(
        db,
        action="workspace_evidence_checklist_created",
        entity_type="incident",
        entity_id=incident.id,
        message=f"Workspace evidence checklist created {created} evidence records.",
        severity=incident.severity or "info",
        actor_username=user.username,
        actor_role=user.role,
    )
    db.commit()
    db.refresh(activity)
    await websocket_manager.broadcast_activity({"type": "activity_created", "activity": serialize_activity(activity)})
    await websocket_manager.broadcast_event("case_evidence_added", {"incident_id": incident.id})
    await websocket_manager.broadcast_dashboard_metrics(db)
    return {"created": created, "incident_id": incident.id}


@router.post("/escalate/attack-chain/{chain_id}", summary="Escalate attack chain to incident")
async def escalate_attack_chain_incident(
    chain_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> dict:
    """Create or update an incident from a critical attack chain."""
    chain = _load_attack_chain(db, chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Attack chain not found")
    chain_payload = serialize_attack_chain(chain)
    recommendation = recommend_for_attack_chain(chain_payload)
    result = escalate_attack_chain(db, chain_payload, recommendation)
    await _finalize_escalation(db, user, result)
    return result


@router.post("/escalate/campaign/{campaign_id}", summary="Escalate campaign to incident")
async def escalate_campaign_incident(
    campaign_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> dict:
    """Create or update an incident from a high-risk campaign cluster."""
    campaign = _load_campaign(db, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign cluster not found")
    campaign_payload = serialize_campaign(campaign)
    recommendation = recommend_for_campaign(campaign_payload)
    result = escalate_campaign(db, campaign_payload, recommendation)
    await _finalize_escalation(db, user, result)
    return result


@router.post("/escalate/context", summary="Escalate supplied context to incident")
async def escalate_context_incident(
    payload: dict,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> dict:
    """Create or update an incident from bounded caller-supplied context."""
    entity_type = str(payload.get("entity_type") or "context")
    entity_id = str(payload.get("entity_id") or "ad_hoc")
    context = payload.get("context") or payload.get("payload") or {}
    if not isinstance(context, dict):
        raise HTTPException(status_code=400, detail="context must be an object")
    recommendation = payload.get("recommendation")
    if not isinstance(recommendation, dict):
        recommendation = recommend_for_context(entity_type, entity_id, context)
    result = escalate_context(db, entity_type=entity_type, entity_id=entity_id, context=context, recommendation=recommendation)
    await _finalize_escalation(db, user, result)
    return result


async def _finalize_escalation(db: Session, user: models.User, result: dict) -> None:
    severity = "critical" if result.get("priority") == "critical" else "high" if result.get("escalated") else "info"
    action = "incident_escalated" if result.get("escalated") else "incident_escalation_skipped"
    activity = add_activity(
        db,
        action=action,
        entity_type="incident",
        entity_id=result.get("incident_id"),
        message=result.get("reason") or "Incident escalation evaluated.",
        severity=severity,
        actor_username=user.username,
        actor_role=user.role,
    )
    db.commit()
    if result.get("incident_id"):
        incident = db.get(models.Incident, result["incident_id"])
        if incident:
            db.refresh(incident)
    db.refresh(activity)
    await websocket_manager.broadcast_activity({"type": "activity_created", "activity": serialize_activity(activity)})
    await websocket_manager.broadcast_event(
        "incident_escalated",
        {
            "incident_id": result.get("incident_id"),
            "created": result.get("created"),
            "linked_entity_type": result.get("linked_entity_type"),
            "linked_entity_id": result.get("linked_entity_id"),
        },
    )
    await websocket_manager.broadcast_dashboard_metrics(db)


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
