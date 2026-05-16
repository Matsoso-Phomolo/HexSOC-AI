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
    agent_version: str | None = None
    host_name: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    last_event_count: int | None = None
    last_error: str | None = None
    heartbeat_count: int = 0
    last_heartbeat_at: datetime | None = None
    health_status: str = "offline"
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


class CollectorHeartbeatResponse(BaseModel):
    """Heartbeat response returned to external live collectors."""

    collector_name: str
    collector_type: str
    status: str
    last_seen_at: datetime | None = None
    last_heartbeat_at: datetime | None = None
    heartbeat_count: int = 0
    health_status: str = "online"


class CollectorHeartbeatRequest(BaseModel):
    """Optional health payload sent by live agents."""

    agent_version: str | None = None
    host_name: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    last_event_count: int | None = None
    last_error: str | None = None


class CollectorHealthSummary(BaseModel):
    """Fleet health response for live collectors."""

    total_collectors: int
    online: int
    degraded: int = 0
    stale: int
    offline: int
    revoked: int
    collectors: list[CollectorRead]


class CollectorFleetGroup(BaseModel):
    """Small count bucket used by fleet summary responses."""

    key: str
    count: int


class CollectorFleetSummary(BaseModel):
    """Bounded operational summary for the collector fleet."""

    total_collectors: int
    status_counts: dict[str, int]
    type_distribution: list[CollectorFleetGroup]
    source_distribution: list[CollectorFleetGroup]
    os_distribution: list[CollectorFleetGroup]
    version_distribution: list[CollectorFleetGroup]
    stale_collectors: list[CollectorRead]
    offline_collectors: list[CollectorRead]
    version_drift: list[CollectorRead]
    telemetry_volume_total: int
    last_seen_age_seconds_max: int | None = None
    heartbeat_age_seconds_max: int | None = None


class CollectorFleetDetail(BaseModel):
    """Detailed collector view with derived operational metadata."""

    collector: CollectorRead
    last_seen_age_seconds: int | None = None
    heartbeat_age_seconds: int | None = None
    telemetry_volume: int
    version_drift: bool
    local_control_note: str
