from pydantic import BaseModel


class Detection(BaseModel):
    """Detection rule contract."""

    id: str
    name: str
    enabled: bool = True
