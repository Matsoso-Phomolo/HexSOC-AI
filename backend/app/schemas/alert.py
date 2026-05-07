from datetime import datetime

from pydantic import BaseModel


class AlertCreate(BaseModel):
    """Input contract for creating an analyst-facing alert."""

    title: str
    severity: str = "medium"
    status: str = "open"
    source: str | None = None
    description: str | None = None
    event_id: int | None = None


class AlertStatusUpdate(BaseModel):
    """Input contract for changing alert lifecycle status."""

    status: str


class AlertRead(AlertCreate):
    """Stored alert returned by the API."""

    id: int
    created_at: datetime
    updated_at: datetime | None = None

    class Config:
        orm_mode = True
        from_attributes = True
