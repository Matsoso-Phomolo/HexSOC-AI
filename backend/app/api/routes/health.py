from datetime import UTC, datetime

from fastapi import APIRouter
from sqlalchemy import text

from app.core.config import settings
from app.db.database import engine

router = APIRouter(tags=["health"])


@router.get("/health", summary="Service health check")
def health_check() -> dict[str, str]:
    """Return service and database health for deployment checks."""
    database_status = "ok"

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception:
        database_status = "error"

    return {
        "service": settings.app_name,
        "status": "ok" if database_status == "ok" else "degraded",
        "environment": settings.app_env,
        "database": database_status,
        "timestamp": datetime.now(UTC).isoformat(),
    }
