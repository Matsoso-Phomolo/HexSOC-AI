"""Authentication routes for HexSOC AI."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
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


@router.post("/register", response_model=UserRead, status_code=201, summary="Register user")
def register_user(payload: UserCreate, db: Session = Depends(get_db)) -> models.User:
    """Create a user account with a safe default analyst role."""
    exists = (
        db.query(models.User)
        .filter(or_(models.User.email == payload.email, models.User.username == payload.username))
        .first()
    )
    if exists:
        raise HTTPException(status_code=409, detail="Email or username already exists")

    user = models.User(
        full_name=payload.full_name,
        email=payload.email.lower(),
        username=payload.username.lower(),
        hashed_password=hash_password(payload.password),
        role=normalize_role(payload.role),
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse, summary="Login")
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    """Authenticate a user and return a bearer token."""
    user = get_user_by_login(db, payload.username.lower())
    if user is None or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is inactive")
    return TokenResponse(access_token=create_access_token(user), user=user)


@router.get("/me", response_model=CurrentUser, summary="Current user")
def read_me(user: models.User = Depends(get_current_user)) -> models.User:
    """Return the authenticated user."""
    return user
