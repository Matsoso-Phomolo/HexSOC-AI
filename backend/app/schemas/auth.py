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
    disabled_reason: str | None = None
    last_login_at: datetime | None = None
    updated_at: datetime | None = None
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


class UserSessionRead(BaseModel):
    """Safe session object returned to users/admins."""

    id: int
    user_id: int
    session_id: str
    created_at: datetime | None = None
    last_seen_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    revoked_reason: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    is_active: bool
    suspicious: bool = False


class LoginAttemptRead(BaseModel):
    """Login attempt governance record."""

    id: int
    email_or_username: str
    ip_address: str | None = None
    user_agent: str | None = None
    outcome: str
    reason: str | None = None
    created_at: datetime | None = None
