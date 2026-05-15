"""Schemas for the Threat Intelligence Feed Integrator."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


IOCType = Literal["ip", "domain", "url", "hash", "email", "cve"]


class ThreatIOCCreate(BaseModel):
    """Input contract for one normalized or raw threat indicator."""

    ioc_type: IOCType | None = None
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
    raw_context: dict[str, Any] | None = None


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
    fingerprint: str | None = None
    source: str
    sources: list[str] | None = None
    source_count: int | None = None
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
    raw_context: dict[str, Any] | None = None
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
    total_received: int
    created: int
    updated: int
    skipped: int
    source: str
    errors: list[dict[str, str]] = Field(default_factory=list)
    indicators: list[ThreatIOCRead]


class IOCSearchResponse(BaseModel):
    """Search response for normalized IOC lookups."""

    query: str
    total: int
    indicators: list[ThreatIOCRead]


class IOCCorrelateRequest(BaseModel):
    """Request to correlate raw indicators against stored IOCs."""

    indicators: list[str] = Field(default_factory=list, max_length=100)


class IOCLiveCorrelationResponse(BaseModel):
    """Correlation result for supplied raw indicators."""

    inputs_checked: int
    matches_found: int
    risk_amplification: int
    results: list[dict[str, Any]]
    graph_relationships: list[dict[str, Any]]


class ThreatIntelSyncStatus(BaseModel):
    """Operational status of the local IOC intelligence lifecycle."""

    active_iocs: int
    expired_iocs: int
    source_count: int
    link_count: int
    top_sources: list[dict[str, Any]]


class IOCGraphEnrichmentRequest(BaseModel):
    """Request to enrich one SOC entity with matching IOC graph relationships."""

    entity_type: Literal["alert", "event", "asset", "incident"]
    entity_id: int
    indicators: list[str] = Field(default_factory=list, max_length=100)


class IOCGraphEnrichmentResponse(BaseModel):
    """Bounded graph-native IOC enrichment response."""

    entity_node: dict[str, Any]
    ioc_nodes: list[dict[str, Any]]
    relationships: list[dict[str, Any]]
    summary: dict[str, Any]


class IOCRelationshipSummary(BaseModel):
    """Summary of stored IOC relationships."""

    total_relationships: int
    by_entity_type: list[dict[str, Any]]
    recent_relationships: list[dict[str, Any]]
    highest_weighted_relationships: list[dict[str, Any]] = Field(default_factory=list)
    top_ioc_types: list[dict[str, Any]] = Field(default_factory=list)


class ThreatProviderEnrichRequest(BaseModel):
    """Explicit threat provider enrichment request."""

    indicators: list[str] = Field(default_factory=list, max_length=100)
    providers: list[Literal["virustotal", "abuseipdb", "otx", "misp"]] | None = None
    persist: bool = False


class AutoCorrelateRequest(BaseModel):
    """Automated threat intelligence correlation request."""

    entity_type: Literal["event", "alert", "asset", "incident", "raw"]
    entity_id: int | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    use_providers: bool = False
    persist_relationships: bool = True


class AutoCorrelateResponse(BaseModel):
    """Automated threat intelligence correlation summary."""

    entity_type: str
    entity_id: str | None = None
    indicators_extracted: int
    local_matches: int
    provider_matches: int
    relationships_created: int
    risk_amplification: int
    max_confidence: int
    classification: str
    matched_iocs: list[dict[str, Any]]
    relationships: list[dict[str, Any]]
    provider_errors: list[dict[str, Any]]


class IOCCorrelationResponse(BaseModel):
    """Summary for IOC correlation across SOC entities."""

    active_iocs_checked: int
    links_created: int
    links_existing: int
    expired_iocs_deactivated: int
