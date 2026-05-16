"""Correlation and attack-chain endpoints."""

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.security.permissions import Permission, require_permission
from app.services.correlation_engine import run_correlation
from app.services.websocket_manager import serialize_activity, websocket_manager

router = APIRouter()


@router.post("/run", summary="Run correlation engine")
async def run_correlation_engine(
    db: Session = Depends(get_db),
    user: models.User = Depends(require_permission(Permission.CORRELATION_RUN)),
) -> dict[str, Any]:
    """Build attack-chain candidates from current SOC records."""
    result = run_correlation(db)
    activity = result.pop("activity")
    payload = {
        "type": "correlation_completed",
        "chains_found": result["chains_found"],
        "source_ips_checked": result["source_ips_checked"],
        "chains": result["chains"],
    }

    await websocket_manager.broadcast_activity(
        {"type": "activity_created", "activity": serialize_activity(activity)}
    )
    await websocket_manager.broadcast_activity(payload)
    await websocket_manager.broadcast_activity({"type": "graph_updated"})
    await websocket_manager.broadcast_dashboard_metrics(db)

    return result
