"""Investigation graph endpoints."""

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.services.graph_engine import build_investigation_graph

router = APIRouter()


@router.get("/investigation", summary="Get investigation graph")
def get_investigation_graph(
    source_ip: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    limit: int = Query(default=150, ge=25, le=500),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Return graph-ready SOC relationships for analyst investigation."""
    return build_investigation_graph(db, source_ip=source_ip, severity=severity, limit=limit)
