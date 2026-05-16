from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.security.permissions import Permission, require_permission
from app.services.detection_engine import RULES, run_detection_rules
from app.services.websocket_manager import websocket_manager

router = APIRouter()


@router.get("/", summary="List detections")
def list_detections() -> dict[str, list]:
    """Return available rule-based detections."""
    return {"items": RULES}


@router.post("/run", summary="Run detection engine")
async def run_detections(
    db: Session = Depends(get_db),
    user: models.User = Depends(require_permission(Permission.DETECTION_RUN)),
) -> dict[str, int]:
    """Scan recent security events and create alerts for rule matches."""
    result = run_detection_rules(db)
    created_alerts = result.pop("_created_alerts", [])
    created_activities = result.pop("_created_activities", [])

    for alert in created_alerts:
        await websocket_manager.broadcast_alert({"type": "alert_created", "alert": alert})

    for activity in created_activities:
        await websocket_manager.broadcast_activity({"type": "activity_created", "activity": activity})

    await websocket_manager.broadcast_dashboard_metrics(db)
    return {
        "rules_checked": int(result["rules_checked"]),
        "alerts_created": int(result["alerts_created"]),
        "matches_found": int(result["matches_found"]),
    }
