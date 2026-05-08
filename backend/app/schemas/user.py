"""Schemas for admin user management."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class UserAdminRead(BaseModel):
    """Safe user record for admin management views."""

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


class UserUpdate(BaseModel):
    """Editable profile fields for an existing SOC user."""

    full_name: str | None = None
    email: str | None = None


class UserRoleUpdate(BaseModel):
    """Role change payload for admin user workflows."""

    role: str


class UserDeactivateRequest(BaseModel):
    """Optional deactivation reason captured for audit context."""

    disabled_reason: str | None = None


class LoginAuditRead(BaseModel):
    """Authentication audit event returned to admins."""

    id: int
    user_id: int | None = None
    username: str
    success: bool
    reason: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserDetailRead(UserAdminRead):
    """User detail with recent login audit preview."""

    login_audits: list[LoginAuditRead] = []
