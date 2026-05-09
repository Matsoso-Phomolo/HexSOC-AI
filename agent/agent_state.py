"""Persistent state and duplicate prevention for the HexSOC Agent."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


AGENT_DIR = Path(__file__).resolve().parent
DEFAULT_STATE_PATH = AGENT_DIR / "data" / "agent_state.json"
DEFAULT_HISTORY_LIMIT = 5000
FINGERPRINT_FIELDS = (
    "timestamp",
    "event_type",
    "source",
    "source_ip",
    "destination_ip",
    "username",
    "hostname",
    "raw_message",
)
SECRET_KEYS = {"api_key", "collector_api_key", "HEXSOC_API_KEY", "X-HexSOC-API-Key"}


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def default_state() -> dict[str, Any]:
    """Return a fresh agent state document."""
    return {
        "last_run_at": None,
        "last_event_cursor": None,
        "windows_event_cursors": {},
        "sent_event_fingerprints": [],
        "total_events_sent": 0,
        "total_batches_sent": 0,
        "total_duplicates_skipped": 0,
    }


def normalize_path(path: str | Path | None) -> Path:
    """Resolve agent state paths from repo or agent working directories."""
    if path is None:
        return DEFAULT_STATE_PATH
    state_path = Path(path)
    if state_path.is_absolute():
        return state_path
    if state_path.parts and state_path.parts[0] == "agent":
        return AGENT_DIR.parent / state_path
    return AGENT_DIR / state_path


def load_state(path: str | Path | None = None) -> dict[str, Any]:
    """Load agent state, creating defaults when missing."""
    state_path = normalize_path(path)
    if not state_path.exists():
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state = default_state()
        save_state(state_path, state)
        return state
    with state_path.open("r", encoding="utf-8") as file:
        payload = json.load(file)
    if not isinstance(payload, dict):
        return default_state()
    state = default_state()
    state.update(payload)
    return state


def save_state(path: str | Path | None, state: dict[str, Any]) -> None:
    """Persist agent state as JSON."""
    state_path = normalize_path(path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    with state_path.open("w", encoding="utf-8") as file:
        json.dump(state, file, indent=2, sort_keys=True)


def update_last_run(state: dict[str, Any]) -> None:
    """Update last run timestamp."""
    state["last_run_at"] = utc_now()


def get_sent_fingerprints(state: dict[str, Any]) -> set[str]:
    """Return sent fingerprints as a set."""
    values = state.get("sent_event_fingerprints")
    if not isinstance(values, list):
        return set()
    return {str(value) for value in values}


def add_sent_fingerprints(state: dict[str, Any], fingerprints: list[str], limit: int = DEFAULT_HISTORY_LIMIT) -> None:
    """Append sent fingerprints and prune bounded history."""
    existing = list(state.get("sent_event_fingerprints") or [])
    seen = set(existing)
    for fingerprint in fingerprints:
        if fingerprint not in seen:
            existing.append(fingerprint)
            seen.add(fingerprint)
    state["sent_event_fingerprints"] = existing[-max(1, limit) :]
    if fingerprints:
        state["last_event_cursor"] = fingerprints[-1]


def increment_counters(state: dict[str, Any], events_sent: int = 0, batches_sent: int = 0, duplicates_skipped: int = 0) -> None:
    """Increment cumulative state counters."""
    state["total_events_sent"] = int(state.get("total_events_sent", 0) or 0) + events_sent
    state["total_batches_sent"] = int(state.get("total_batches_sent", 0) or 0) + batches_sent
    state["total_duplicates_skipped"] = int(state.get("total_duplicates_skipped", 0) or 0) + duplicates_skipped


def get_windows_event_cursors(state: dict[str, Any]) -> dict[str, int]:
    """Return Windows Event Log cursors by channel."""
    cursors = state.get("windows_event_cursors")
    if not isinstance(cursors, dict):
        return {}
    normalized: dict[str, int] = {}
    for channel, value in cursors.items():
        try:
            normalized[str(channel)] = int(value)
        except (TypeError, ValueError):
            continue
    return normalized


def update_windows_event_cursors(state: dict[str, Any], cursors: dict[str, int]) -> None:
    """Merge Windows Event Log cursors into state."""
    current = get_windows_event_cursors(state)
    for channel, value in cursors.items():
        current[str(channel)] = max(int(value), current.get(str(channel), 0))
    state["windows_event_cursors"] = current


def reset_windows_event_cursors(state: dict[str, Any]) -> None:
    """Clear Windows Event Log cursors."""
    state["windows_event_cursors"] = {}


def sanitize_event(event: dict[str, Any]) -> dict[str, Any]:
    """Remove accidental secret fields before fingerprinting."""
    return {key: value for key, value in event.items() if key not in SECRET_KEYS}


def event_fingerprint(event: dict[str, Any]) -> str:
    """Create a stable SHA-256 fingerprint from deterministic event fields."""
    safe_event = sanitize_event(event)
    canonical = {field: safe_event.get(field) for field in FINGERPRINT_FIELDS}
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def filter_new_events(
    events: list[dict[str, Any]],
    state: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str], int]:
    """Return unseen events, their fingerprints, and duplicate count."""
    sent = get_sent_fingerprints(state)
    new_events: list[dict[str, Any]] = []
    new_fingerprints: list[str] = []
    duplicates = 0
    cycle_seen: set[str] = set()
    for event in events:
        fingerprint = event_fingerprint(event)
        if fingerprint in sent or fingerprint in cycle_seen:
            duplicates += 1
            continue
        new_events.append(event)
        new_fingerprints.append(fingerprint)
        cycle_seen.add(fingerprint)
    return new_events, new_fingerprints, duplicates
