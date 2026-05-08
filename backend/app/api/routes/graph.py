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
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Return graph-ready SOC relationships for analyst investigation."""
    normalized_source_ip = source_ip.strip() if source_ip and source_ip.strip() else None
    normalized_severity = severity.strip().lower() if severity and severity.strip() else None
    return build_investigation_graph(
        db,
        source_ip=normalized_source_ip,
        severity=normalized_severity,
        limit=limit,
    )
