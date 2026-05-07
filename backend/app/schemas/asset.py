from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AssetCreate(BaseModel):
    """Input contract for creating an enterprise asset."""

    hostname: str
    ip_address: str | None = None
    operating_system: str | None = None
    role: str | None = None
    status: str | None = None
    asset_type: str | None = None
    environment: str | None = None
    criticality: str | None = None
    owner: str | None = None


class AssetRead(AssetCreate):
    """Stored asset returned by the API."""

    id: int
    created_at: datetime
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)
