from datetime import datetime

from pydantic import BaseModel


class AssetCreate(BaseModel):
    """Input contract for creating an enterprise asset."""

    hostname: str
    ip_address: str | None = None
    asset_type: str | None = None
    environment: str | None = None
    criticality: str | None = None
    owner: str | None = None


class AssetRead(AssetCreate):
    """Stored asset returned by the API."""

    id: int
    created_at: datetime
    updated_at: datetime | None = None

    class Config:
        orm_mode = True
        from_attributes = True
