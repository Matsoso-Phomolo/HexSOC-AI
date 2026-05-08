"""Schemas for real log ingestion."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class IngestLogItem(BaseModel):
    """Normalized incoming log item from collectors or external telemetry."""

    timestamp: datetime | None = None
    event_type: str
    source: str = "external"
    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None
    hostname: str | None = None
    severity: str = "low"
    raw_message: str | None = None
    raw_payload: dict[str, Any] | None = None

    model_config = ConfigDict(extra="allow")


class IngestedEventSummary(BaseModel):
    """Summary for one ingested event."""

    event_id: int
    event_type: str
    severity: str
    asset_id: int | None = None
    hostname: str | None = None
    source_ip: str | None = None


class BulkIngestRequest(BaseModel):
    """Bulk ingestion request body."""

    logs: list[IngestLogItem]


class BulkIngestResponse(BaseModel):
    """Result summary for ingestion operations."""

    received: int
    ingested: int
    skipped: int
    assets_created: int
    events: list[IngestedEventSummary]
    validation_errors: list[str] = []
    detections_run: bool = False
    detection_summary: dict[str, int] | None = None
