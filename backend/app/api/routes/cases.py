"""Case management endpoints for SOC incidents."""

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.schemas.case import CaseEvidenceCreate, CaseEvidenceRead, CaseNoteCreate, CaseNoteRead, CaseUpdate
from app.schemas.incident import IncidentRead
from app.services.activity_service import add_activity
from app.services.ai_copilot_service import summarize_incident
from app.services.websocket_manager import serialize_activity, websocket_manager

router = APIRouter()


@router.get("/", response_model=list[IncidentRead], summary="List cases")
def list_cases(db: Session = Depends(get_db)) -> list[models.Incident]:
    """Return incidents as SOC cases ordered by newest first."""
    return db.query(models.Incident).order_by(models.Incident.id.desc()).all()


@router.get("/{incident_id}", response_model=IncidentRead, summary="Get case")
def get_case(incident_id: int, db: Session = Depends(get_db)) -> models.Incident:
    """Return one incident case."""
    return _get_incident(db, incident_id)


@router.patch("/{incident_id}", response_model=IncidentRead, summary="Update case")
async def update_case(
    incident_id: int,
    payload: CaseUpdate,
    db: Session = Depends(get_db),
) -> models.Incident:
    """Update assignment, priority, escalation, and case closure metadata."""
    incident = _get_incident(db, incident_id)
    previous_assignee = incident.assigned_to
    previous_status = incident.case_status

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(incident, field, value)

    activities: list[models.ActivityLog] = []
    if payload.assigned_to is not None and payload.assigned_to != previous_assignee:
        activities.append(
            add_activity(
                db,
                action="case_assigned",
                entity_type="incident",
                entity_id=incident.id,
                message=f"Case assigned to {payload.assigned_to or 'unassigned'}.",
                severity=incident.severity or "info",
            )
        )

    if payload.case_status is not None and payload.case_status != previous_status:
        activities.append(
            add_activity(
                db,
                action="case_status_changed",
                entity_type="incident",
                entity_id=incident.id,
                message=f"Case status changed from {previous_status or 'unset'} to {payload.case_status}.",
                severity=incident.severity or "info",
            )
        )

    if not activities:
        activities.append(
            add_activity(
                db,
                action="case_status_changed",
                entity_type="incident",
                entity_id=incident.id,
                message="Case metadata updated.",
                severity=incident.severity or "info",
            )
        )

    db.commit()
    db.refresh(incident)
    await _broadcast_case("case_updated", incident.id, activities, db)
    return incident


@router.post("/{incident_id}/notes", response_model=CaseNoteRead, status_code=201, summary="Add case note")
async def add_case_note(
    incident_id: int,
    payload: CaseNoteCreate,
    db: Session = Depends(get_db),
) -> models.CaseNote:
    """Add an analyst note to a case."""
    incident = _get_incident(db, incident_id)
    if not payload.content.strip():
        raise HTTPException(status_code=422, detail="Note content is required")

    note = models.CaseNote(incident_id=incident.id, **payload.model_dump())
    db.add(note)
    db.flush()
    activity = add_activity(
        db,
        action="case_note_added",
        entity_type="incident",
        entity_id=incident.id,
        message=f"Case note added by {note.author}: {note.note_type}.",
        severity=incident.severity or "info",
    )
    db.commit()
    db.refresh(note)
    db.refresh(activity)
    await _broadcast_case("case_note_added", incident.id, [activity], db)
    return note


@router.get("/{incident_id}/notes", response_model=list[CaseNoteRead], summary="List case notes")
def list_case_notes(incident_id: int, db: Session = Depends(get_db)) -> list[models.CaseNote]:
    """Return analyst notes for a case."""
    _get_incident(db, incident_id)
    return (
        db.query(models.CaseNote)
        .filter(models.CaseNote.incident_id == incident_id)
        .order_by(models.CaseNote.id.desc())
        .all()
    )


@router.post("/{incident_id}/evidence", response_model=CaseEvidenceRead, status_code=201, summary="Add case evidence")
async def add_case_evidence(
    incident_id: int,
    payload: CaseEvidenceCreate,
    db: Session = Depends(get_db),
) -> models.CaseEvidence:
    """Add an evidence record to a case."""
    incident = _get_incident(db, incident_id)
    if not payload.title.strip():
        raise HTTPException(status_code=422, detail="Evidence title is required")

    evidence = models.CaseEvidence(incident_id=incident.id, **payload.model_dump())
    db.add(evidence)
    db.flush()
    activity = add_activity(
        db,
        action="case_evidence_added",
        entity_type="incident",
        entity_id=incident.id,
        message=f"Case evidence added: {evidence.title}.",
        severity=incident.severity or "info",
    )
    db.commit()
    db.refresh(evidence)
    db.refresh(activity)
    await _broadcast_case("case_evidence_added", incident.id, [activity], db)
    return evidence


@router.get("/{incident_id}/evidence", response_model=list[CaseEvidenceRead], summary="List case evidence")
def list_case_evidence(incident_id: int, db: Session = Depends(get_db)) -> list[models.CaseEvidence]:
    """Return evidence records for a case."""
    _get_incident(db, incident_id)
    return (
        db.query(models.CaseEvidence)
        .filter(models.CaseEvidence.incident_id == incident_id)
        .order_by(models.CaseEvidence.id.desc())
        .all()
    )


@router.get("/{incident_id}/report", summary="Generate case report")
async def generate_case_report(incident_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Return a structured JSON SOC case report."""
    incident = _get_incident(db, incident_id)
    notes = list_case_notes(incident_id, db)
    evidence = list_case_evidence(incident_id, db)
    related_alerts = _related_alerts(db, incident)
    related_events = _related_events(db, related_alerts)
    copilot = summarize_incident(incident)

    activity = add_activity(
        db,
        action="case_report_generated",
        entity_type="incident",
        entity_id=incident.id,
        message=f"JSON SOC report generated for case {incident.id}.",
        severity=incident.severity or "info",
    )
    db.commit()
    db.refresh(activity)
    await _broadcast_case("case_report_generated", incident.id, [activity], db)
    timeline = _timeline(db, incident_id)

    return {
        "incident_summary": _incident_dict(incident),
        "assigned_analyst": incident.assigned_to,
        "severity": incident.severity,
        "priority": incident.priority,
        "status": incident.case_status or incident.status,
        "related_alerts": [_alert_dict(alert) for alert in related_alerts],
        "related_events": [_event_dict(event) for event in related_events],
        "analyst_notes": [_note_dict(note) for note in notes],
        "evidence": [_evidence_dict(item) for item in evidence],
        "recommended_response": copilot,
        "timeline_summary": [_activity_dict(item) for item in timeline],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _get_incident(db: Session, incident_id: int) -> models.Incident:
    incident = db.get(models.Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return incident


async def _broadcast_case(
    event_type: str,
    incident_id: int,
    activities: list[models.ActivityLog],
    db: Session,
) -> None:
    for activity in activities:
        db.refresh(activity)
        await websocket_manager.broadcast_activity(
            {"type": "activity_created", "activity": serialize_activity(activity)}
        )
    await websocket_manager.broadcast_activity({"type": event_type, "incident_id": incident_id})


def _related_alerts(db: Session, incident: models.Incident) -> list[models.Alert]:
    if not incident.alert_id:
        return []
    alert = db.get(models.Alert, incident.alert_id)
    return [alert] if alert else []


def _related_events(db: Session, alerts: list[models.Alert]) -> list[models.SecurityEvent]:
    event_ids = [alert.event_id for alert in alerts if alert.event_id]
    if not event_ids:
        return []
    return db.query(models.SecurityEvent).filter(models.SecurityEvent.id.in_(event_ids)).all()


def _timeline(db: Session, incident_id: int) -> list[models.ActivityLog]:
    return (
        db.query(models.ActivityLog)
        .filter(
            or_(
                models.ActivityLog.entity_type == "incident",
                models.ActivityLog.entity_type == "attack_chain",
            ),
            or_(
                models.ActivityLog.entity_id == incident_id,
                models.ActivityLog.entity_id.is_(None),
            ),
        )
        .order_by(models.ActivityLog.id.desc())
        .limit(25)
        .all()
    )


def _incident_dict(incident: models.Incident) -> dict[str, Any]:
    return {
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "case_status": incident.case_status,
        "priority": incident.priority,
        "assigned_to": incident.assigned_to,
        "escalation_level": incident.escalation_level,
        "resolution_summary": incident.resolution_summary,
        "closed_at": _iso(incident.closed_at),
    }


def _alert_dict(alert: models.Alert) -> dict[str, Any]:
    return {
        "id": alert.id,
        "title": alert.title,
        "severity": alert.severity,
        "status": alert.status,
        "detection_rule": alert.detection_rule,
        "threat_score": alert.threat_score,
    }


def _event_dict(event: models.SecurityEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "event_type": event.event_type,
        "source_ip": event.source_ip,
        "severity": event.severity,
        "summary": event.summary,
    }


def _note_dict(note: models.CaseNote) -> dict[str, Any]:
    return {
        "id": note.id,
        "author": note.author,
        "note_type": note.note_type,
        "content": note.content,
        "created_at": _iso(note.created_at),
    }


def _evidence_dict(evidence: models.CaseEvidence) -> dict[str, Any]:
    return {
        "id": evidence.id,
        "evidence_type": evidence.evidence_type,
        "title": evidence.title,
        "description": evidence.description,
        "source": evidence.source,
        "reference_id": evidence.reference_id,
        "created_at": _iso(evidence.created_at),
    }


def _activity_dict(activity: models.ActivityLog) -> dict[str, Any]:
    return {
        "id": activity.id,
        "action": activity.action,
        "message": activity.message,
        "severity": activity.severity,
        "created_at": _iso(activity.created_at),
    }


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None
