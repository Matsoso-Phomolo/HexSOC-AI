"""Authentication routes for HexSOC AI."""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.db.database import sync_phase2_schema
from app.schemas.auth import CurrentUser, LoginRequest, TokenResponse, UserCreate, UserRead
from app.services.auth_service import (
    APPROVAL_REQUIRED_ROLES,
    PENDING_PRIVILEGED_APPROVAL_REASON,
    create_access_token,
    get_current_user,
    get_user_by_login,
    hash_password,
    normalize_role,
    verify_password,
)
from app.services.audit_log_service import log_failure, log_success

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/register", response_model=UserRead, status_code=201, summary="Register user")
def register_user(payload: UserCreate, request: Request, db: Session = Depends(get_db)) -> models.User:
    """Create a user account with a safe default analyst role."""
    email = payload.email.strip().lower()
    username = payload.username.strip().lower()

    try:
        exists = _find_existing_user(db, email, username)
    except SQLAlchemyError:
        logger.exception("Auth register user lookup failed; attempting schema sync")
        db.rollback()
        _sync_auth_schema_or_503()
        try:
            exists = _find_existing_user(db, email, username)
        except SQLAlchemyError as exc:
            logger.exception("Auth register user lookup failed after schema sync")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication database is not ready. Please retry after deployment startup completes.",
            ) from exc

    if exists:
        log_failure(
            db,
            action="user_registration_rejected",
            category="auth",
            request=request,
            target_type="user",
            target_label=username,
            metadata={"reason": "duplicate_identity", "requested_role": payload.role},
        )
        db.commit()
        raise HTTPException(status_code=409, detail="Email or username already exists")

    requested_role = normalize_role(payload.role)
    requires_approval = requested_role in APPROVAL_REQUIRED_ROLES
    user = models.User(
        full_name=payload.full_name,
        email=email,
        username=username,
        hashed_password=hash_password(payload.password),
        role=requested_role,
        is_active=not requires_approval,
        disabled_reason=PENDING_PRIVILEGED_APPROVAL_REASON if requires_approval else None,
    )

    try:
        db.add(user)
        db.commit()
        db.refresh(user)
        log_success(
            db,
            action="user_registered",
            category="auth",
            actor=user,
            request=request,
            target_type="user",
            target_id=user.id,
            target_label=user.username,
            metadata={"requested_role": requested_role, "requires_approval": requires_approval},
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        if _is_duplicate_user_identity_error(exc):
            logger.info("Duplicate registration rejected for username=%s email=%s", username, email)
            raise HTTPException(status_code=409, detail="Email or username already exists") from exc
        logger.exception("Auth register integrity failure for username=%s email=%s", username, email)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not create user account because the authentication database rejected the record.",
        ) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Auth register failed for username=%s email=%s", username, email)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not create user account because the authentication database is unavailable.",
        ) from exc

    return user


@router.post("/login", response_model=TokenResponse, summary="Login")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    """Authenticate a user and return a bearer token."""
    username = payload.username.strip().lower()
    try:
        user = get_user_by_login(db, username)
    except SQLAlchemyError as exc:
        logger.exception("Auth login lookup failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication database is unavailable.",
        ) from exc

    if user is None or not verify_password(payload.password, user.hashed_password):
        _record_login_audit(db, request, user=None, username=username, success=False, reason="invalid_credentials")
        log_failure(
            db,
            action="login_failed",
            category="auth",
            request=request,
            target_type="user",
            target_label=username,
            metadata={"reason": "invalid_credentials"},
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.is_active:
        _record_login_audit(db, request, user=user, username=user.username, success=False, reason="inactive_account")
        log_failure(
            db,
            action="login_blocked",
            category="auth",
            actor=user,
            request=request,
            target_type="user",
            target_id=user.id,
            target_label=user.username,
            metadata={"reason": "inactive_account", "disabled_reason": user.disabled_reason},
        )
        db.commit()
        detail = user.disabled_reason or "User is inactive"
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)

    user.last_login_at = datetime.now(timezone.utc)
    _record_login_audit(db, request, user=user, username=user.username, success=True, reason="login_success")
    db.add(user)
    db.commit()
    db.refresh(user)
    log_success(
        db,
        action="login_success",
        category="auth",
        actor=user,
        request=request,
        target_type="user",
        target_id=user.id,
        target_label=user.username,
    )
    db.commit()
    return TokenResponse(access_token=create_access_token(user), user=user)


@router.get("/me", response_model=CurrentUser, summary="Current user")
def read_me(user: models.User = Depends(get_current_user)) -> models.User:
    """Return the authenticated user."""
    return user


def _find_existing_user(db: Session, email: str, username: str) -> models.User | None:
    return db.query(models.User).filter(or_(models.User.email == email, models.User.username == username)).first()


def _sync_auth_schema_or_503() -> None:
    try:
        sync_phase2_schema()
    except SQLAlchemyError as exc:
        logger.exception("Auth schema sync failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication database schema could not be initialized.",
        ) from exc


def _is_duplicate_user_identity_error(exc: IntegrityError) -> bool:
    detail = str(getattr(exc, "orig", exc)).lower()
    constraint = getattr(getattr(exc, "orig", None), "diag", None)
    constraint_name = getattr(constraint, "constraint_name", "") or ""
    combined = f"{detail} {constraint_name}".lower()
    return "email" in combined or "username" in combined


def _record_login_audit(
    db: Session,
    request: Request,
    *,
    user: models.User | None,
    username: str,
    success: bool,
    reason: str,
) -> None:
    try:
        audit = models.LoginAudit(
            user_id=user.id if user else None,
            username=username,
            success=success,
            reason=reason,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        db.add(audit)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Login audit write failed for username=%s", username)
