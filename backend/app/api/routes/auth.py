"""Authentication routes for HexSOC AI."""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.db.database import sync_phase2_schema
from app.schemas.auth import CurrentUser, LoginRequest, TokenResponse, UserCreate, UserRead
from app.services.auth_service import (
    create_access_token,
    get_current_user,
    get_user_by_login,
    hash_password,
    normalize_role,
    verify_password,
)

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/register", response_model=UserRead, status_code=201, summary="Register user")
def register_user(payload: UserCreate, db: Session = Depends(get_db)) -> models.User:
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
        raise HTTPException(status_code=409, detail="Email or username already exists")

    user = models.User(
        full_name=payload.full_name,
        email=email,
        username=username,
        hashed_password=hash_password(payload.password),
        role=normalize_role(payload.role),
        is_active=True,
    )

    try:
        db.add(user)
        db.commit()
        db.refresh(user)
    except IntegrityError as exc:
        db.rollback()
        logger.info("Duplicate registration rejected for username=%s email=%s", username, email)
        raise HTTPException(status_code=409, detail="Email or username already exists") from exc
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Auth register failed for username=%s email=%s", username, email)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not create user account because the authentication database is unavailable.",
        ) from exc

    return user


@router.post("/login", response_model=TokenResponse, summary="Login")
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    """Authenticate a user and return a bearer token."""
    try:
        user = get_user_by_login(db, payload.username.strip().lower())
    except SQLAlchemyError as exc:
        logger.exception("Auth login lookup failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication database is unavailable.",
        ) from exc

    if user is None or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is inactive")
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
