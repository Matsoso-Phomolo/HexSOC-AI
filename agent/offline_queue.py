"""Offline telemetry queue for the HexSOC Agent.

The queue stores failed telemetry payloads as JSON lines and never persists
collector API keys. Queue files are local runtime state and must stay ignored by
git.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
import socket
import ssl
from urllib import error, request


AGENT_DIR = Path(__file__).resolve().parent
DEFAULT_QUEUE_PATH = AGENT_DIR / "data" / "offline_queue.jsonl"
DEFAULT_DEAD_LETTER_PATH = AGENT_DIR / "data" / "dead_letter_queue.jsonl"
SECRET_KEYS = {"api_key", "collector_api_key", "HEXSOC_API_KEY", "X-HexSOC-API-Key"}


PostFunc = Callable[[str, str, dict[str, Any]], dict[str, Any]]


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def normalize_path(path: str | Path | None, default: Path = DEFAULT_QUEUE_PATH) -> Path:
    """Resolve queue paths consistently from repo or agent working directories."""
    if path is None:
        return default
    queue_path = Path(path)
    if queue_path.is_absolute():
        return queue_path
    if queue_path.parts and queue_path.parts[0] == "agent":
        return AGENT_DIR.parent / queue_path
    return AGENT_DIR / queue_path


def dead_letter_path_for(queue_path: str | Path | None = None, dead_letter_path: str | Path | None = None) -> Path:
    """Resolve the dead-letter path matching a queue path."""
    if dead_letter_path is not None:
        return normalize_path(dead_letter_path, DEFAULT_DEAD_LETTER_PATH)
    if queue_path is None:
        return DEFAULT_DEAD_LETTER_PATH
    resolved_queue_path = normalize_path(queue_path)
    return resolved_queue_path.with_name("dead_letter_queue.jsonl")


def sanitize_payload(value: Any) -> Any:
    """Remove accidental secret fields before queue persistence."""
    if isinstance(value, dict):
        return {key: sanitize_payload(item) for key, item in value.items() if key not in SECRET_KEYS}
    if isinstance(value, list):
        return [sanitize_payload(item) for item in value]
    return value


def append_json_line(path: Path, record: dict[str, Any]) -> None:
    """Append one JSON object to a JSONL file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record, sort_keys=True) + "\n")


def write_queue(items: list[dict[str, Any]], queue_path: str | Path | None = None) -> None:
    """Rewrite the queue with the provided items."""
    path = normalize_path(queue_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not items:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8") as file:
        for item in items:
            file.write(json.dumps(item, sort_keys=True) + "\n")


def enqueue(endpoint: str, payload: dict[str, Any], reason: str | None = None, queue_path: str | Path | None = None) -> dict[str, Any]:
    """Queue a failed telemetry request without storing collector secrets."""
    record = {
        "id": str(uuid.uuid4()),
        "created_at": utc_now(),
        "endpoint": endpoint,
        "payload": sanitize_payload(payload),
        "attempts": 0,
        "last_error": reason,
    }
    append_json_line(normalize_path(queue_path), record)
    return record


def load_queue(queue_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Load all valid queued records."""
    path = normalize_path(queue_path)
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue
            payload = json.loads(line)
            if isinstance(payload, dict):
                records.append(payload)
    return records


def queue_size(queue_path: str | Path | None = None) -> int:
    """Return pending queue item count."""
    return len(load_queue(queue_path))


def dead_letter_size(dead_letter_path: str | Path | None = None) -> int:
    """Return dead-letter queue item count."""
    return len(load_queue(dead_letter_path or DEFAULT_DEAD_LETTER_PATH))


def clear_successful_items(remaining_items: list[dict[str, Any]] | None = None, queue_path: str | Path | None = None) -> None:
    """Persist remaining failed items after successful flushes."""
    write_queue(remaining_items or [], queue_path)


class QueueNetworkError(RuntimeError):
    """Controlled offline queue network failure."""


def post_json(url: str, api_key: str, payload: dict[str, Any]) -> dict[str, Any]:
    """POST JSON using collector API key authentication."""
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-HexSOC-API-Key": api_key,
            "User-Agent": "HexSOC-Agent/0.1",
        },
    )
    try:
        with request.urlopen(req, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HexSOC API returned {exc.code}: {detail}") from exc
    except (TimeoutError, socket.timeout, ssl.SSLError, error.URLError, ConnectionError, OSError) as exc:
        reason = exc.reason if isinstance(exc, error.URLError) else str(exc)
        raise QueueNetworkError(f"Could not reach HexSOC backend: {reason}") from exc


def flush_queue(
    backend_url: str,
    api_key: str,
    queue_path: str | Path | None = None,
    dead_letter_path: str | Path | None = None,
    max_retry_attempts: int = 10,
    post_func: PostFunc | None = None,
) -> dict[str, int]:
    """Attempt to send queued telemetry and keep failed items for retry."""
    queue_file = normalize_path(queue_path)
    dead_letter_file = dead_letter_path_for(queue_file, dead_letter_path)
    pending = load_queue(queue_file)
    remaining: list[dict[str, Any]] = []
    flushed = 0
    failed = 0
    dead_lettered = 0
    sender = post_func or post_json
    backend = backend_url.rstrip("/")

    for item in pending:
        endpoint = str(item.get("endpoint") or "")
        payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}
        try:
            sender(f"{backend}{endpoint}", api_key, payload)
            flushed += 1
        except Exception as exc:  # noqa: BLE001 - queue must preserve failures robustly.
            item["attempts"] = int(item.get("attempts", 0) or 0) + 1
            item["last_error"] = str(exc)
            if item["attempts"] >= max_retry_attempts:
                append_json_line(dead_letter_file, item)
                dead_lettered += 1
            else:
                remaining.append(item)
                failed += 1

    clear_successful_items(remaining, queue_file)
    return {
        "pending_before": len(pending),
        "flushed": flushed,
        "failed": failed,
        "dead_lettered": dead_lettered,
        "pending_after": len(remaining),
    }


def clear_queue(queue_path: str | Path | None = None, dead_letter_path: str | Path | None = None) -> None:
    """Clear pending and dead-letter queues."""
    write_queue([], queue_path)
    write_queue([], dead_letter_path_for(queue_path, dead_letter_path))
