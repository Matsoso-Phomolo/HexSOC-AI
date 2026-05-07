from datetime import datetime

from pydantic import BaseModel, ConfigDict


class IncidentCreate(BaseModel):
    """Input contract for creating an incident case."""

    title: str
    severity: str = "medium"
    status: str = "open"
    summary: str | None = None
    description: str | None = None
    alert_id: int | None = None


class IncidentStatusUpdate(BaseModel):
    """Input contract for changing incident lifecycle status."""

    status: str


class IncidentRead(IncidentCreate):
    """Stored incident returned by the API."""

    id: int
    title: str | None = None
    severity: str | None = None
    status: str | None = None
    created_at: datetime
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)
