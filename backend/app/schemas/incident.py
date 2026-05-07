from datetime import datetime

from pydantic import BaseModel


class IncidentCreate(BaseModel):
    """Input contract for creating an incident case."""

    title: str
    severity: str = "medium"
    status: str = "open"
    summary: str | None = None


class IncidentRead(IncidentCreate):
    """Stored incident returned by the API."""

    id: int
    created_at: datetime
    updated_at: datetime | None = None

    class Config:
        orm_mode = True
        from_attributes = True
