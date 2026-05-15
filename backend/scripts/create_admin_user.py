"""Create a HexSOC AI admin user from environment variables."""

import os

from app.db.database import SessionLocal, init_db
from app.db import models
from app.services.auth_service import hash_password


def main() -> None:
    init_db()
    email = os.getenv("ADMIN_EMAIL")
    username = os.getenv("ADMIN_USERNAME")
    password = os.getenv("ADMIN_PASSWORD")
    full_name = os.getenv("ADMIN_FULL_NAME", "HexSOC Admin")
    reset_password = os.getenv("ADMIN_RESET_PASSWORD", "false").strip().lower() in {"1", "true", "yes", "y"}

    if not all([email, username, password]):
        raise SystemExit("ADMIN_EMAIL, ADMIN_USERNAME, and ADMIN_PASSWORD are required.")

    db = SessionLocal()
    try:
        normalized_email = email.lower()
        normalized_username = username.lower()
        existing = (
            db.query(models.User)
            .filter((models.User.email == normalized_email) | (models.User.username == normalized_username))
            .first()
        )
        if existing:
            existing.email = normalized_email
            existing.username = normalized_username
            existing.full_name = full_name
            existing.role = "admin"
            existing.is_active = True
            if reset_password:
                existing.hashed_password = hash_password(password)
            db.commit()
            if reset_password:
                print(f"Admin user already exists, was ensured active, and password was reset: {existing.username}")
            else:
                print(f"Admin user already exists and was ensured active: {existing.username}")
            return

        user = models.User(
            full_name=full_name,
            email=normalized_email,
            username=normalized_username,
            hashed_password=hash_password(password),
            role="admin",
            is_active=True,
        )
        db.add(user)
        db.commit()
        print(f"Created admin user: {user.username}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
