from datetime import datetime

from pydantic import BaseModel, ConfigDict


class UserCreate(BaseModel):
    """Input contract for registering a HexSOC AI user."""

    full_name: str
    email: str
    username: str
    password: str
    role: str = "analyst"


class UserRead(BaseModel):
    """Safe user object returned to clients."""

    id: int
    full_name: str
    email: str
    username: str
    role: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class LoginRequest(BaseModel):
    """Username/email and password login request."""

    username: str
    password: str


class CurrentUser(UserRead):
    """Authenticated user returned by /me."""


class TokenResponse(BaseModel):
    """Access token response for frontend sessions."""

    access_token: str
    token_type: str = "bearer"
    user: UserRead
