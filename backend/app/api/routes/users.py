"""Admin-only user management routes."""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.db.database import sync_phase2_schema
from app.schemas.user import (
    LoginAuditRead,
    UserAdminRead,
    UserDeactivateRequest,
    UserDetailRead,
    UserRoleUpdate,
    UserUpdate,
)
from app.services.activity_service import add_activity
from app.services.auth_service import (
    APPROVAL_REQUIRED_ROLES,
    PENDING_ADMIN_APPROVAL_REASON,
    PENDING_PRIVILEGED_APPROVAL_REASON,
    SUPER_ADMIN_EMAIL,
    is_pending_admin_approval,
    is_super_admin,
    normalize_role,
    require_role,
)
from app.services.websocket_manager import serialize_activity, websocket_manager

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/", response_model=list[UserAdminRead], summary="List users")
def list_users(
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("admin")),
) -> list[UserAdminRead]:
    """Return all SOC users for admin review."""
    try:
        users = _query_users(db)
    except SQLAlchemyError:
        logger.exception("Admin user list failed; attempting schema sync")
        db.rollback()
        _sync_users_schema_or_503()
        try:
            users = _query_users(db)
        except SQLAlchemyError as exc:
            logger.exception("Admin user list failed after schema sync")
            raise HTTPException(status_code=503, detail="User management database is not ready.") from exc
    return [_user_read(user) for user in users]


@router.get("/{user_id}", response_model=UserDetailRead, summary="Get user")
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_role("admin")),
) -> UserDetailRead:
    """Return one user with recent login audit activity."""
    try:
        user = _get_user_or_404(db, user_id)
        audits = _recent_audits(db, user)
    except SQLAlchemyError:
        logger.exception("Admin user detail failed; attempting schema sync")
        db.rollback()
        _sync_users_schema_or_503()
        user = _get_user_or_404(db, user_id)
        audits = _recent_audits(db, user)
    return _detail_response(user, audits)


@router.patch("/{user_id}", response_model=UserAdminRead, summary="Update user")
async def update_user(
    user_id: int,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    actor: models.User = Depends(require_role("admin")),
) -> UserAdminRead:
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
    return _user_read(user)


@router.post("/{user_id}/activate", response_model=UserAdminRead, summary="Activate user")
async def activate_user(
    user_id: int,
    db: Session = Depends(get_db),
    actor: models.User = Depends(require_role("admin")),
) -> UserAdminRead:
    """Reactivate a SOC user account."""
    user = _get_user_or_404(db, user_id)
    if is_pending_admin_approval(user) and not is_super_admin(actor):
        raise HTTPException(
            status_code=403,
            detail=f"Analyst/admin registration approval is restricted to PHOMOLO MATSOSO ({SUPER_ADMIN_EMAIL}).",
        )
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
    return _user_read(user)


@router.post("/{user_id}/deactivate", response_model=UserAdminRead, summary="Deactivate user")
async def deactivate_user(
    user_id: int,
    payload: UserDeactivateRequest | None = None,
    db: Session = Depends(get_db),
    actor: models.User = Depends(require_role("admin")),
) -> UserAdminRead:
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
    return _user_read(user)


@router.post("/{user_id}/disapprove", response_model=UserAdminRead, summary="Disapprove pending privileged user")
async def disapprove_user(
    user_id: int,
    db: Session = Depends(get_db),
    actor: models.User = Depends(require_role("admin")),
) -> UserAdminRead:
    """Disapprove a pending analyst/admin registration request."""
    _require_super_admin(actor)
    user = _get_user_or_404(db, user_id)
    if user.id == actor.id:
        raise HTTPException(status_code=400, detail="Super admin cannot disapprove their own account")
    if user.role not in APPROVAL_REQUIRED_ROLES or user.is_active:
        raise HTTPException(status_code=400, detail="Only pending analyst/admin requests can be disapproved")

    user.is_active = False
    user.disabled_reason = f"Disapproved by PHOMOLO MATSOSO ({SUPER_ADMIN_EMAIL})"
    user.updated_at = datetime.now(timezone.utc)
    activity = add_activity(
        db,
        action="user_disapproved",
        entity_type="user",
        entity_id=user.id,
        message=f"User {user.username} {user.role} request disapproved.",
        severity="warning",
        actor_username=actor.username,
        actor_role=actor.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    db.refresh(activity)
    await _broadcast_user_action("user_disapproved", user, activity)
    return _user_read(user)


@router.delete("/{user_id}", summary="Delete user")
async def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    actor: models.User = Depends(require_role("admin")),
) -> dict:
    """Permanently delete a SOC user. Restricted to the designated super admin."""
    _require_super_admin(actor)
    user = _get_user_or_404(db, user_id)
    if user.id == actor.id:
        raise HTTPException(status_code=400, detail="Super admin cannot delete their own account")

    deleted_username = user.username
    deleted_role = user.role
    db.query(models.LoginAudit).filter(models.LoginAudit.user_id == user.id).delete(synchronize_session=False)
    activity = add_activity(
        db,
        action="user_deleted",
        entity_type="user",
        entity_id=user.id,
        message=f"User {deleted_username} ({deleted_role}) deleted by super admin.",
        severity="critical",
        actor_username=actor.username,
        actor_role=actor.role,
    )
    db.delete(user)
    db.commit()
    db.refresh(activity)
    await websocket_manager.broadcast_activity({"type": "activity_created", "activity": serialize_activity(activity)})
    await websocket_manager.broadcast_activity(
        {"type": "user_deleted", "user_id": user_id, "username": deleted_username, "role": deleted_role}
    )
    return {"deleted": True, "user_id": user_id, "username": deleted_username, "role": deleted_role}


@router.post("/{user_id}/role", response_model=UserAdminRead, summary="Change user role")
async def change_user_role(
    user_id: int,
    payload: UserRoleUpdate,
    db: Session = Depends(get_db),
    actor: models.User = Depends(require_role("admin")),
) -> UserAdminRead:
    """Change a SOC user's role."""
    user = _get_user_or_404(db, user_id)
    next_role = normalize_role(payload.role)
    if next_role in APPROVAL_REQUIRED_ROLES and not is_super_admin(actor):
        raise HTTPException(
            status_code=403,
            detail=f"Only PHOMOLO MATSOSO ({SUPER_ADMIN_EMAIL}) can approve or grant analyst/admin access.",
        )
    previous_role = user.role
    user.role = next_role
    if next_role in APPROVAL_REQUIRED_ROLES and is_super_admin(actor):
        user.is_active = True
        if user.disabled_reason in {PENDING_ADMIN_APPROVAL_REASON, PENDING_PRIVILEGED_APPROVAL_REASON}:
            user.disabled_reason = None
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
    return _user_read(user)


def _get_user_or_404(db: Session, user_id: int) -> models.User:
    user = db.get(models.User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


def _require_super_admin(actor: models.User) -> None:
    if not is_super_admin(actor):
        raise HTTPException(
            status_code=403,
            detail=f"Only PHOMOLO MATSOSO ({SUPER_ADMIN_EMAIL}) can perform this action.",
        )


def _query_users(db: Session) -> list[models.User]:
    return db.query(models.User).order_by(models.User.id.asc()).all()


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
        **_user_read(user).model_dump(),
        login_audits=[LoginAuditRead.model_validate(audit) for audit in audits],
    )


def _user_read(user: models.User) -> UserAdminRead:
    return UserAdminRead(
        id=user.id,
        full_name=user.full_name or user.username or user.email or f"User {user.id}",
        email=user.email or f"user_{user.id}@hexsoc.local",
        username=user.username or f"user_{user.id}",
        role=normalize_role(user.role),
        is_active=bool(user.is_active),
        disabled_reason=user.disabled_reason,
        last_login_at=user.last_login_at,
        updated_at=user.updated_at,
        created_at=user.created_at or datetime.now(timezone.utc),
    )


def _sync_users_schema_or_503() -> None:
    try:
        sync_phase2_schema()
    except SQLAlchemyError as exc:
        logger.exception("Admin users schema sync failed")
        raise HTTPException(status_code=503, detail="User management schema could not be initialized.") from exc


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
