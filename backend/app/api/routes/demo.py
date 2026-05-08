from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.config import settings
from app.services.demo_seed_service import seed_demo_data

router = APIRouter()


@router.post("/seed", summary="Seed demo SOC data")
def seed_demo(
    db: Session = Depends(get_db),
    x_demo_seed_token: str | None = Header(default=None),
) -> dict:
    """Seed demo data safely for local and protected demo environments."""
    is_production = settings.app_env.lower() == "production"

    if is_production:
        if not settings.demo_seed_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Demo seeding is disabled in production.",
            )

        if x_demo_seed_token != settings.demo_seed_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid demo seed token.",
            )

    result = seed_demo_data(db)
    return {"status": "ok", "result": result}
