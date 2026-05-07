from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ActivityRead(BaseModel):
    """SOC activity timeline record returned by the API."""

    id: int
    action: str
    entity_type: str
    entity_id: int | None = None
    message: str
    severity: str = "info"
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
