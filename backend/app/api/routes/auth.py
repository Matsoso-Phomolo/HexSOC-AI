"""Authentication routes for HexSOC AI."""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.db.database import sync_phase2_schema
from app.schemas.auth import CurrentUser, LoginAttemptRead, LoginRequest, TokenResponse, UserCreate, UserRead, UserSessionRead
from app.security.permissions import Permission, has_permission
from app.services.auth_service import (
    APPROVAL_REQUIRED_ROLES,
    PENDING_PRIVILEGED_APPROVAL_REASON,
    create_access_token,
    get_current_user,
    get_user_by_login,
    hash_password,
    normalize_role,
    verify_password,
    decode_access_token,
)
from app.services.audit_log_service import log_failure, log_success
from app.services.session_security_service import (
    BLOCKED,
    FAILURE,
    LOCKED_OUT,
    SUCCESS,
    create_user_session,
    is_identity_locked,
    login_attempt_to_dict,
    record_login_attempt,
    revoke_session,
    revoke_user_sessions,
    session_to_dict,
)

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

    if is_identity_locked(db, username, request=request):
        record_login_attempt(db, username=username, request=request, outcome=LOCKED_OUT, reason="temporary_lockout")
        _record_login_audit(db, request, user=user, username=username, success=False, reason="temporary_lockout")
        log_failure(
            db,
            action="account_lockout",
            category="auth",
            actor=user,
            request=request,
            target_type="user",
            target_id=user.id if user else None,
            target_label=username,
            metadata={"reason": "too_many_failed_login_attempts"},
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many failed login attempts. Try again later.")

    if user is None or not verify_password(payload.password, user.hashed_password):
        record_login_attempt(db, username=username, request=request, outcome=FAILURE, reason="invalid_credentials")
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
        record_login_attempt(db, username=username, request=request, outcome=BLOCKED, reason="inactive_account")
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
    session = create_user_session(db, user, request=request)
    record_login_attempt(db, username=username, request=request, outcome=SUCCESS, reason="login_success")
    _record_login_audit(db, request, user=user, username=user.username, success=True, reason="login_success")
    db.add(user)
    db.commit()
    db.refresh(user)
    db.refresh(session)
    log_success(
        db,
        action="login_success",
        category="auth",
        actor=user,
        request=request,
        target_type="user",
        target_id=user.id,
        target_label=user.username,
        metadata={"session_id": session.token_jti, "expires_at": session.expires_at},
    )
    db.commit()
    return TokenResponse(access_token=create_access_token(user, token_jti=session.token_jti), user=user)


@router.get("/me", response_model=CurrentUser, summary="Current user")
def read_me(user: models.User = Depends(get_current_user)) -> models.User:
    """Return the authenticated user."""
    return user


@router.get("/sessions", response_model=list[UserSessionRead], summary="List active sessions")
def list_sessions(
    all_users: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[dict]:
    """Return own sessions, or all sessions for admins with audit visibility."""
    query = db.query(models.UserSession)
    if all_users and has_permission(user, Permission.AUDIT_READ):
        query = query.order_by(models.UserSession.id.desc())
    else:
        query = query.filter(models.UserSession.user_id == user.id).order_by(models.UserSession.id.desc())
    return [session_to_dict(session) for session in query.limit(limit).all()]


@router.post("/sessions/revoke/{session_id}", summary="Revoke one session")
def revoke_auth_session(
    session_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> dict:
    """Revoke one session owned by current user, or any session for admins."""
    session = db.query(models.UserSession).filter(models.UserSession.token_jti == session_id).first()
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.user_id != user.id and not has_permission(user, Permission.AUDIT_READ):
        raise HTTPException(status_code=403, detail="Insufficient permission: audit.read required")
    revoke_session(db, session, reason="manual_revoke")
    log_success(
        db,
        action="session_revoked",
        category="auth",
        actor=user,
        request=request,
        target_type="session",
        target_id=session.id,
        target_label=session.token_jti,
        metadata={"session_user_id": session.user_id},
    )
    db.commit()
    return {"revoked": True, "session_id": session.token_jti}


@router.post("/logout-all", summary="Logout all active sessions")
def logout_all_sessions(
    request: Request,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> dict:
    """Revoke all active sessions for the current user."""
    current_jti = _current_jti(authorization)
    revoked = revoke_user_sessions(db, user.id, reason="logout_all", exclude_jti=None)
    log_success(
        db,
        action="logout_all",
        category="auth",
        actor=user,
        request=request,
        target_type="user",
        target_id=user.id,
        target_label=user.username,
        metadata={"revoked_sessions": revoked, "current_session": current_jti},
    )
    db.commit()
    return {"revoked_sessions": revoked}


@router.get("/login-attempts", response_model=list[LoginAttemptRead], summary="List login attempts")
def list_login_attempts(
    all_users: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[dict]:
    """Return own login attempts, or broader governance view for admins."""
    query = db.query(models.LoginAttempt)
    if all_users and has_permission(user, Permission.AUDIT_READ):
        query = query.order_by(models.LoginAttempt.id.desc())
    else:
        query = (
            query.filter(or_(models.LoginAttempt.email_or_username == user.username, models.LoginAttempt.email_or_username == user.email))
            .order_by(models.LoginAttempt.id.desc())
        )
    return [login_attempt_to_dict(attempt) for attempt in query.limit(limit).all()]


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


def _current_jti(authorization: str | None) -> str | None:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    try:
        return decode_access_token(authorization.split(" ", 1)[1]).get("jti")
    except HTTPException:
        return None
