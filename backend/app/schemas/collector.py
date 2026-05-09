"""Schemas for live telemetry collectors."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class CollectorCreate(BaseModel):
    """Input contract for creating a live collector."""

    name: str
    description: str | None = None
    collector_type: str = "custom_json"
    source_label: str | None = None


class CollectorUpdate(BaseModel):
    """Editable collector fields."""

    name: str | None = None
    description: str | None = None
    collector_type: str | None = None
    source_label: str | None = None
    is_active: bool | None = None


class CollectorRead(BaseModel):
    """Collector metadata without raw API key or hash."""

    id: int
    name: str
    description: str | None = None
    key_prefix: str
    collector_type: str
    source_label: str | None = None
    is_active: bool
    last_seen_at: datetime | None = None
    created_by: str | None = None
    created_at: datetime
    revoked_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class CollectorCreatedResponse(BaseModel):
    """Collector creation response with one-time raw API key."""

    collector: CollectorRead
    api_key: str


class CollectorRotateResponse(BaseModel):
    """Collector rotation response with one-time raw API key."""

    collector: CollectorRead
    api_key: str
