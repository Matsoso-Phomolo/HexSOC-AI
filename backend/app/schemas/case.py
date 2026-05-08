from datetime import datetime

from pydantic import BaseModel, ConfigDict


class CaseUpdate(BaseModel):
    """Input contract for updating incident case metadata."""

    assigned_to: str | None = None
    priority: str | None = None
    case_status: str | None = None
    escalation_level: str | None = None
    resolution_summary: str | None = None
    closed_at: datetime | None = None


class CaseNoteCreate(BaseModel):
    """Input contract for adding analyst notes to a case."""

    author: str = "analyst"
    note_type: str = "investigation"
    content: str


class CaseNoteRead(CaseNoteCreate):
    """Stored analyst note returned by the API."""

    id: int
    incident_id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CaseEvidenceCreate(BaseModel):
    """Input contract for adding evidence to a case."""

    evidence_type: str = "analyst_upload_placeholder"
    title: str
    description: str | None = None
    source: str | None = None
    reference_id: str | None = None


class CaseEvidenceRead(CaseEvidenceCreate):
    """Stored evidence returned by the API."""

    id: int
    incident_id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
