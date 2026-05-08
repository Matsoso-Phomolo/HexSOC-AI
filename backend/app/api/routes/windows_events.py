"""Windows and Sysmon raw event ingestion routes."""

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.api.routes.ingestion import _ingest
from app.db import models
from app.schemas.ingestion import BulkIngestResponse
from app.services.auth_service import require_role
from app.services.windows_event_parser import parse_windows_event, parse_windows_events

router = APIRouter()


@router.post("/windows-event", response_model=BulkIngestResponse, status_code=201, summary="Ingest Windows event")
async def ingest_windows_event(
    payload: dict[str, Any],
    auto_detect: bool = Query(default=False),
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> BulkIngestResponse:
    """Parse one raw Windows/Sysmon event and ingest it as a normalized security event."""
    parsed = parse_windows_event(payload)
    response = await _ingest(
        [parsed],
        auto_detect=auto_detect,
        db=db,
        user=user,
        event_type="windows_event_ingested",
        bulk_event_type="bulk_windows_ingestion_completed",
        activity_action="windows_event_ingested",
        activity_message="Windows/Sysmon event ingestion completed.",
    )
    response.received = 1
    return response


@router.post("/windows-events/bulk", response_model=BulkIngestResponse, status_code=201, summary="Bulk ingest Windows events")
async def ingest_windows_events_bulk(
    payload: dict[str, Any] | list[dict[str, Any]],
    auto_detect: bool = Query(default=False),
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("analyst")),
) -> BulkIngestResponse:
    """Parse a batch of raw Windows/Sysmon events and ingest normalized events."""
    raw_events = payload.get("events") if isinstance(payload, dict) else payload
    raw_events = raw_events or payload.get("logs") if isinstance(payload, dict) else raw_events
    parsed, parse_errors = parse_windows_events(raw_events if isinstance(raw_events, list) else [])
    response = await _ingest(
        parsed,
        auto_detect=auto_detect,
        db=db,
        user=user,
        event_type="windows_event_ingested",
        bulk_event_type="bulk_windows_ingestion_completed",
        activity_action="bulk_windows_event_ingestion_completed",
        activity_message="Bulk Windows/Sysmon event ingestion completed.",
    )
    response.received = len(raw_events) if isinstance(raw_events, list) else 0
    response.skipped += len(parse_errors)
    response.validation_errors.extend(parse_errors)
    return response
