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

    if not all([email, username, password]):
        raise SystemExit("ADMIN_EMAIL, ADMIN_USERNAME, and ADMIN_PASSWORD are required.")

    db = SessionLocal()
    try:
        existing = (
            db.query(models.User)
            .filter((models.User.email == email.lower()) | (models.User.username == username.lower()))
            .first()
        )
        if existing:
            existing.role = "admin"
            existing.is_active = True
            db.commit()
            print(f"Admin user already exists and was ensured active: {existing.username}")
            return

        user = models.User(
            full_name=full_name,
            email=email.lower(),
            username=username.lower(),
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
