from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class EventCreate(BaseModel):
    """Input contract for creating a normalized security event."""

    source: str
    event_type: str
    severity: str = "low"
    summary: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None
    raw_message: str | None = None
    asset_id: int | None = None
    raw_payload: dict[str, Any] | None = None


class EventRead(EventCreate):
    """Stored security event returned by the API."""

    id: int
    created_at: datetime
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)
