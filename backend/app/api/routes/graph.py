"""Investigation graph endpoints."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.security.permissions import Permission, require_permission
from app.services.graph_engine import build_investigation_graph
from app.services.ioc_graph_enrichment import graph_ioc_relationships

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/investigation", summary="Get investigation graph")
def get_investigation_graph(
    source_ip: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    node_type: str | None = Query(default=None),
    mitre_tactic: str | None = Query(default=None),
    hostname: str | None = Query(default=None),
    time_window: str | None = Query(default=None),
    aggregate: bool = Query(default=True),
    limit: int = Query(default=150, ge=1, le=500),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_permission(Permission.GRAPH_READ)),
) -> dict[str, Any]:
    """Return graph-ready SOC relationships for analyst investigation."""
    normalized_source_ip = source_ip.strip() if source_ip and source_ip.strip() else None
    normalized_severity = severity.strip().lower() if severity and severity.strip() else None
    normalized_node_type = node_type.strip() if node_type and node_type.strip() else None
    normalized_mitre_tactic = mitre_tactic.strip() if mitre_tactic and mitre_tactic.strip() else None
    normalized_hostname = hostname.strip() if hostname and hostname.strip() else None
    normalized_time_window = time_window.strip().lower() if time_window and time_window.strip() else None
    try:
        return build_investigation_graph(
            db,
            source_ip=normalized_source_ip,
            severity=normalized_severity,
            node_type=normalized_node_type,
            mitre_tactic=normalized_mitre_tactic,
            hostname=normalized_hostname,
            time_window=normalized_time_window,
            aggregate=aggregate,
            limit=limit,
        )
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Investigation graph query failed: %s", exc)
    except Exception as exc:
        logger.exception("Investigation graph serialization failed: %s", exc)
    return _empty_graph_payload(error="graph_unavailable")


@router.get("/ioc-relationships", summary="Get IOC graph relationships")
def get_ioc_relationship_graph(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_permission(Permission.GRAPH_READ)),
) -> dict[str, Any]:
    """Return bounded IOC relationship nodes and edges for graph investigation."""
    try:
        return graph_ioc_relationships(db, limit=limit)
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("IOC relationship graph query failed: %s", exc)
    except Exception as exc:
        logger.exception("IOC relationship graph serialization failed: %s", exc)
    return _empty_graph_payload(error="ioc_relationship_graph_unavailable")


def _empty_graph_payload(error: str | None = None) -> dict[str, Any]:
    return {
        "nodes": [],
        "edges": [],
        "summary": {
            "nodes": 0,
            "edges": 0,
            "high_risk_nodes": 0,
            "high_risk_relationships": 0,
            "high_risk_clusters": 0,
            "top_source_ips": [],
            "top_techniques": [],
            "most_connected_assets": [],
            "aggregation": "fallback",
            "error": error,
        },
    }
