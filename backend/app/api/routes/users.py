"""Admin-only user management routes."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.schemas.user import (
    LoginAuditRead,
    UserAdminRead,
    UserDeactivateRequest,
    UserDetailRead,
    UserRoleUpdate,
    UserUpdate,
)
from app.services.activity_service import add_activity
from app.services.auth_service import normalize_role, require_role
from app.services.websocket_manager import serialize_activity, websocket_manager

router = APIRouter()


@router.get("/", response_model=list[UserAdminRead], summary="List users")
def list_users(
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("admin")),
) -> list[models.User]:
    """Return all SOC users for admin review."""
    return db.query(models.User).order_by(models.User.id.asc()).all()


@router.get("/{user_id}", response_model=UserDetailRead, summary="Get user")
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("admin")),
) -> UserDetailRead:
    """Return one user with recent login audit activity."""
    user = _get_user_or_404(db, user_id)
    audits = _recent_audits(db, user)
    return _detail_response(user, audits)


@router.patch("/{user_id}", response_model=UserAdminRead, summary="Update user")
async def update_user(
    user_id: int,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    actor: models.User = Depends(require_role("admin")),
) -> models.User:
    """Update editable identity fields for a SOC user."""
    user = _get_user_or_404(db, user_id)

    if payload.full_name is not None:
        user.full_name = payload.full_name.strip()
    if payload.email is not None:
        user.email = payload.email.strip().lower()

    user.updated_at = datetime.now(timezone.utc)
    activity = add_activity(
        db,
        action="user_updated",
        entity_type="user",
        entity_id=user.id,
        message=f"User {user.username} profile updated.",
        severity="info",
        actor_username=actor.username,
        actor_role=actor.role,
    )
    db.add(user)

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Email already exists") from exc

    db.refresh(user)
    db.refresh(activity)
    await _broadcast_user_action("user_updated", user, activity)
    return user


@router.post("/{user_id}/activate", response_model=UserAdminRead, summary="Activate user")
async def activate_user(
    user_id: int,
    db: Session = Depends(get_db),
    actor: models.User = Depends(require_role("admin")),
) -> models.User:
    """Reactivate a SOC user account."""
    user = _get_user_or_404(db, user_id)
    user.is_active = True
    user.disabled_reason = None
    user.updated_at = datetime.now(timezone.utc)
    activity = add_activity(
        db,
        action="user_activated",
        entity_type="user",
        entity_id=user.id,
        message=f"User {user.username} activated.",
        severity="info",
        actor_username=actor.username,
        actor_role=actor.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    db.refresh(activity)
    await _broadcast_user_action("user_activated", user, activity)
    return user


@router.post("/{user_id}/deactivate", response_model=UserAdminRead, summary="Deactivate user")
async def deactivate_user(
    user_id: int,
    payload: UserDeactivateRequest | None = None,
    db: Session = Depends(get_db),
    actor: models.User = Depends(require_role("admin")),
) -> models.User:
    """Deactivate a SOC user account without allowing self-lockout."""
    user = _get_user_or_404(db, user_id)
    if user.id == actor.id:
        raise HTTPException(status_code=400, detail="Admins cannot deactivate their own account")

    user.is_active = False
    user.disabled_reason = (payload.disabled_reason.strip() if payload and payload.disabled_reason else None)
    user.updated_at = datetime.now(timezone.utc)
    activity = add_activity(
        db,
        action="user_deactivated",
        entity_type="user",
        entity_id=user.id,
        message=f"User {user.username} deactivated.",
        severity="warning",
        actor_username=actor.username,
        actor_role=actor.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    db.refresh(activity)
    await _broadcast_user_action("user_deactivated", user, activity)
    return user


@router.post("/{user_id}/role", response_model=UserAdminRead, summary="Change user role")
async def change_user_role(
    user_id: int,
    payload: UserRoleUpdate,
    db: Session = Depends(get_db),
    actor: models.User = Depends(require_role("admin")),
) -> models.User:
    """Change a SOC user's role."""
    user = _get_user_or_404(db, user_id)
    next_role = normalize_role(payload.role)
    previous_role = user.role
    user.role = next_role
    user.updated_at = datetime.now(timezone.utc)
    activity = add_activity(
        db,
        action="user_role_changed",
        entity_type="user",
        entity_id=user.id,
        message=f"User {user.username} role changed from {previous_role} to {next_role}.",
        severity="info",
        actor_username=actor.username,
        actor_role=actor.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    db.refresh(activity)
    await _broadcast_user_action("user_role_changed", user, activity)
    return user


def _get_user_or_404(db: Session, user_id: int) -> models.User:
    user = db.get(models.User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


def _recent_audits(db: Session, user: models.User) -> list[models.LoginAudit]:
    return (
        db.query(models.LoginAudit)
        .filter(models.LoginAudit.username == user.username)
        .order_by(models.LoginAudit.id.desc())
        .limit(8)
        .all()
    )


def _detail_response(user: models.User, audits: list[models.LoginAudit]) -> UserDetailRead:
    return UserDetailRead(
        **UserAdminRead.model_validate(user).model_dump(),
        login_audits=[LoginAuditRead.model_validate(audit) for audit in audits],
    )


async def _broadcast_user_action(event_type: str, user: models.User, activity: models.ActivityLog) -> None:
    await websocket_manager.broadcast_activity(
        {
            "type": "activity_created",
            "activity": serialize_activity(activity),
        }
    )
    await websocket_manager.broadcast_activity(
        {
            "type": event_type,
            "user_id": user.id,
            "username": user.username,
            "role": user.role,
            "is_active": user.is_active,
        }
    )
