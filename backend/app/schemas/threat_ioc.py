"""Schemas for the Threat Intelligence Feed Integrator."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


IOCType = Literal["ip", "domain", "url", "hash"]


class ThreatIOCCreate(BaseModel):
    """Input contract for one normalized or raw threat indicator."""

    ioc_type: IOCType
    value: str = Field(min_length=1, max_length=1000)
    source: str = Field(default="manual", min_length=1, max_length=120)
    source_reference: str | None = None
    confidence_score: int = Field(default=50, ge=0, le=100)
    risk_score: int = Field(default=50, ge=0, le=100)
    severity: str = "medium"
    tags: list[str] = Field(default_factory=list)
    classification: str | None = None
    description: str | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    expires_at: datetime | None = None
    ttl_days: int | None = Field(default=90, ge=1, le=3650)
    raw_payload: dict[str, Any] | None = None


class ThreatIOCBulkCreate(BaseModel):
    """Bulk ingestion request for feed-normalized indicators."""

    source: str = "manual"
    indicators: list[ThreatIOCCreate]


class ThreatIOCRead(BaseModel):
    """Stored threat indicator returned by the API."""

    id: int
    ioc_type: str
    value: str
    normalized_value: str
    source: str
    source_reference: str | None = None
    confidence_score: int
    risk_score: int
    severity: str
    tags: list[str] | None = None
    classification: str | None = None
    description: str | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    expires_at: datetime | None = None
    is_active: bool
    created_at: datetime
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class ThreatIOCLinkRead(BaseModel):
    """Correlation link between an IOC and a SOC entity."""

    id: int
    ioc_id: int
    entity_type: str
    entity_id: int
    relationship: str
    confidence_score: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FeedNormalizeRequest(BaseModel):
    """Raw feed payload wrapper for adapter-based normalization."""

    source: str
    payload: dict[str, Any] | list[dict[str, Any]]
    default_ttl_days: int = Field(default=90, ge=1, le=3650)


class ThreatIOCIngestResponse(BaseModel):
    """Summary for IOC ingestion operations."""

    received: int
    created: int
    updated: int
    skipped: int
    source: str
    indicators: list[ThreatIOCRead]


class IOCCorrelationResponse(BaseModel):
    """Summary for IOC correlation across SOC entities."""

    active_iocs_checked: int
    links_created: int
    links_existing: int
    expired_iocs_deactivated: int
