"""Case management endpoints for SOC incidents."""

from datetime import datetime, timezone
from html import escape
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.schemas.case import CaseEvidenceCreate, CaseEvidenceRead, CaseNoteCreate, CaseNoteRead, CaseUpdate
from app.schemas.incident import IncidentRead
from app.services.activity_service import add_activity
from app.services.ai_copilot_service import summarize_incident
from app.services.auth_service import decode_access_token, get_current_user, require_role
from app.services.websocket_manager import serialize_activity, websocket_manager

router = APIRouter()


@router.get("/", response_model=list[IncidentRead], summary="List cases")
def list_cases(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[models.Incident]:
    """Return incidents as SOC cases ordered by newest first."""
    return db.query(models.Incident).order_by(models.Incident.id.desc()).all()


@router.get("/{incident_id}", response_model=IncidentRead, summary="Get case")
def get_case(
    incident_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> models.Incident:
    """Return one incident case."""
    return _get_incident(db, incident_id)


@router.patch("/{incident_id}", response_model=IncidentRead, summary="Update case")
async def update_case(
    incident_id: int,
    payload: CaseUpdate,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
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
                actor_username=user.username,
                actor_role=user.role,
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
                actor_username=user.username,
                actor_role=user.role,
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
                actor_username=user.username,
                actor_role=user.role,
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
    user: models.User = Depends(require_role("analyst")),
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
        actor_username=user.username,
        actor_role=user.role,
    )
    db.commit()
    db.refresh(note)
    db.refresh(activity)
    await _broadcast_case("case_note_added", incident.id, [activity], db)
    return note


@router.get("/{incident_id}/notes", response_model=list[CaseNoteRead], summary="List case notes")
def list_case_notes(
    incident_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[models.CaseNote]:
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
    user: models.User = Depends(require_role("analyst")),
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
        actor_username=user.username,
        actor_role=user.role,
    )
    db.commit()
    db.refresh(evidence)
    db.refresh(activity)
    await _broadcast_case("case_evidence_added", incident.id, [activity], db)
    return evidence


@router.get("/{incident_id}/evidence", response_model=list[CaseEvidenceRead], summary="List case evidence")
def list_case_evidence(
    incident_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[models.CaseEvidence]:
    """Return evidence records for a case."""
    _get_incident(db, incident_id)
    return (
        db.query(models.CaseEvidence)
        .filter(models.CaseEvidence.incident_id == incident_id)
        .order_by(models.CaseEvidence.id.desc())
        .all()
    )


@router.get("/{incident_id}/report", summary="Generate case report")
async def generate_case_report(
    incident_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> dict[str, Any]:
    """Return a structured JSON SOC case report."""
    incident = _get_incident(db, incident_id)
    activity = add_activity(
        db,
        action="case_report_generated",
        entity_type="incident",
        entity_id=incident.id,
        message=f"JSON SOC report generated for case {incident.id}.",
        severity=incident.severity or "info",
        actor_username=user.username,
        actor_role=user.role,
    )
    db.commit()
    db.refresh(activity)
    await _broadcast_case("case_report_generated", incident.id, [activity], db)
    return _build_case_report(db, incident)


@router.get("/{incident_id}/report/json", summary="Download case report JSON")
async def export_case_report_json(
    incident_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> JSONResponse:
    """Return a downloadable structured JSON case report."""
    incident = _get_incident(db, incident_id)
    activity = add_activity(
        db,
        action="case_report_json_exported",
        entity_type="incident",
        entity_id=incident.id,
        message=f"JSON SOC report exported for case {incident.id}.",
        severity=incident.severity or "info",
        actor_username=user.username,
        actor_role=user.role,
    )
    db.commit()
    db.refresh(activity)
    await _broadcast_case("case_report_exported", incident.id, [activity], db)
    report = _build_case_report(db, incident)
    filename = f"hexsoc-case-{incident.id}-report.json"
    return JSONResponse(
        content=report,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{incident_id}/report/html", response_class=HTMLResponse, summary="Open printable case report")
async def export_case_report_html(
    incident_id: int,
    token: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """Return a printable HTML case report with embedded styling."""
    user = _user_from_query_token(db, token)
    if user.role not in {"admin", "analyst"}:
        raise HTTPException(status_code=403, detail="Insufficient role")
    incident = _get_incident(db, incident_id)
    activity = add_activity(
        db,
        action="case_report_html_exported",
        entity_type="incident",
        entity_id=incident.id,
        message=f"Printable HTML SOC report exported for case {incident.id}.",
        severity=incident.severity or "info",
        actor_username=user.username,
        actor_role=user.role,
    )
    db.commit()
    db.refresh(activity)
    await _broadcast_case("case_report_exported", incident.id, [activity], db)
    report = _build_case_report(db, incident)
    return HTMLResponse(content=_render_report_html(report))


def _get_incident(db: Session, incident_id: int) -> models.Incident:
    incident = db.get(models.Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return incident


def _user_from_query_token(db: Session, token: str | None) -> models.User:
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
    payload = decode_access_token(token)
    user = db.get(models.User, int(payload["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Inactive or missing user")
    return user


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


def _build_case_report(db: Session, incident: models.Incident) -> dict[str, Any]:
    notes = list_case_notes(incident.id, db)
    evidence = list_case_evidence(incident.id, db)
    related_alerts = _related_alerts(db, incident)
    related_events = _related_events(db, related_alerts)
    copilot = summarize_incident(incident)
    timeline = _timeline(db, incident.id)

    return {
        "brand": "HexSOC AI",
        "report_type": "SOC Case Report",
        "incident_summary": _incident_dict(incident),
        "assigned_analyst": incident.assigned_to,
        "severity": incident.severity,
        "priority": incident.priority,
        "status": incident.case_status or incident.status,
        "escalation_level": incident.escalation_level,
        "related_alerts": [_alert_dict(alert) for alert in related_alerts],
        "related_events": [_event_dict(event) for event in related_events],
        "analyst_notes": [_note_dict(note) for note in notes],
        "evidence": [_evidence_dict(item) for item in evidence],
        "copilot_guidance": copilot,
        "recommended_response": copilot,
        "recommended_actions": copilot.get("recommended_actions", []),
        "timeline_summary": [_activity_dict(item) for item in timeline],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


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


def _render_report_html(report: dict[str, Any]) -> str:
    incident = report["incident_summary"]
    guidance = report.get("copilot_guidance", {})
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>HexSOC AI Case {escape(str(incident.get("id")))} Report</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; color: #111827; font-family: Arial, sans-serif; background: #f8fafc; }}
    header {{ background: #0b1220; color: #e5edf6; padding: 28px 36px; }}
    header p {{ color: #7dd3fc; font-weight: 700; letter-spacing: .04em; margin: 0 0 8px; text-transform: uppercase; }}
    h1 {{ font-size: 28px; margin: 0; }}
    main {{ padding: 28px 36px; }}
    section {{ page-break-inside: avoid; background: #ffffff; border: 1px solid #dbe3ef; border-radius: 8px; margin-bottom: 18px; padding: 18px; }}
    h2 {{ color: #0f172a; font-size: 18px; margin: 0 0 12px; }}
    h3 {{ margin: 14px 0 8px; }}
    .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }}
    .metric {{ background: #f1f5f9; border-radius: 6px; padding: 10px; }}
    .metric span {{ color: #64748b; display: block; font-size: 12px; text-transform: uppercase; }}
    .metric strong {{ color: #0f172a; display: block; margin-top: 4px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border-bottom: 1px solid #e2e8f0; padding: 9px; text-align: left; vertical-align: top; }}
    th {{ background: #f1f5f9; color: #334155; font-size: 12px; text-transform: uppercase; }}
    ul {{ margin: 8px 0 0 20px; padding: 0; }}
    footer {{ color: #64748b; font-size: 12px; padding: 0 36px 28px; text-align: center; }}
    @media print {{ body {{ background: #fff; }} header {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }} section {{ break-inside: avoid; }} }}
  </style>
</head>
<body>
  <header>
    <p>HexSOC AI</p>
    <h1>SOC Case Report: {escape(str(incident.get("title") or "Untitled Case"))}</h1>
  </header>
  <main>
    <section>
      <h2>Incident Summary</h2>
      <div class="grid">
        {_metric("Case ID", incident.get("id"))}
        {_metric("Assigned Analyst", report.get("assigned_analyst") or "Unassigned")}
        {_metric("Severity", report.get("severity"))}
        {_metric("Priority", report.get("priority") or "Unset")}
        {_metric("Case Status", report.get("status"))}
        {_metric("Escalation", report.get("escalation_level") or "Unset")}
      </div>
      <p>{escape(str(incident.get("resolution_summary") or "No resolution summary recorded."))}</p>
    </section>
    <section>
      <h2>Copilot Guidance</h2>
      <p>{escape(str(guidance.get("summary") or ""))}</p>
      <p><strong>Risk:</strong> {escape(str(guidance.get("risk_assessment") or ""))}</p>
      <h3>Recommended Actions</h3>
      {_list(report.get("recommended_actions", []))}
    </section>
    <section>
      <h2>Related Alerts</h2>
      {_table(report.get("related_alerts", []), ["id", "title", "severity", "status", "detection_rule", "threat_score"])}
    </section>
    <section>
      <h2>Related Events</h2>
      {_table(report.get("related_events", []), ["id", "event_type", "source_ip", "severity", "summary"])}
    </section>
    <section>
      <h2>Analyst Notes</h2>
      {_table(report.get("analyst_notes", []), ["created_at", "author", "note_type", "content"])}
    </section>
    <section>
      <h2>Evidence</h2>
      {_table(report.get("evidence", []), ["created_at", "evidence_type", "title", "source", "reference_id", "description"])}
    </section>
    <section>
      <h2>Activity Timeline</h2>
      {_table(report.get("timeline_summary", []), ["created_at", "action", "severity", "message"])}
    </section>
    <section>
      <h2>Report Metadata</h2>
      <p><strong>Generated at:</strong> {escape(str(report.get("generated_at")))}</p>
    </section>
  </main>
  <footer>Generated by HexSOC AI</footer>
</body>
</html>"""


def _metric(label: str, value: Any) -> str:
    return f'<div class="metric"><span>{escape(label)}</span><strong>{escape(str(value or "N/A"))}</strong></div>'


def _list(items: list[Any]) -> str:
    if not items:
        return "<p>No recommended actions available.</p>"
    return "<ul>" + "".join(f"<li>{escape(str(item))}</li>" for item in items) + "</ul>"


def _table(rows: list[dict[str, Any]], columns: list[str]) -> str:
    if not rows:
        return "<p>No records available.</p>"
    header = "".join(f"<th>{escape(column.replace('_', ' '))}</th>" for column in columns)
    body = ""
    for row in rows:
        body += "<tr>" + "".join(f"<td>{escape(str(row.get(column) or ''))}</td>" for column in columns) + "</tr>"
    return f"<table><thead><tr>{header}</tr></thead><tbody>{body}</tbody></table>"


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None
