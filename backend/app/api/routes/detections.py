from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.services.detection_engine import RULES, run_detection_rules

router = APIRouter()


@router.get("/", summary="List detections")
def list_detections() -> dict[str, list]:
    """Return available rule-based detections."""
    return {"items": RULES}


@router.post("/run", summary="Run detection engine")
def run_detections(db: Session = Depends(get_db)) -> dict[str, int]:
    """Scan recent security events and create alerts for rule matches."""
    return run_detection_rules(db)
