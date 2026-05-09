"""Lightweight HexSOC Agent prototype.

This prototype sends Windows/Sysmon telemetry to HexSOC AI through collector
API keys. It intentionally avoids privileged host collection until the agent
contract is stable.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib import error, request


DEFAULT_CONFIG = "config.json"
DEFAULT_EVENTS_FILE = "sample_windows_events.json"


def load_json_file(path: Path) -> dict[str, Any]:
    """Load a JSON object from disk."""
    with path.open("r", encoding="utf-8-sig") as file:
        payload = json.load(file)
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return payload


def normalize_backend_url(value: str) -> str:
    """Normalize backend URL without a trailing slash."""
    return value.rstrip("/")


def post_json(url: str, api_key: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """POST JSON to HexSOC with collector authentication."""
    body = json.dumps(payload or {}).encode("utf-8")
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
    except error.URLError as exc:
        raise RuntimeError(f"Could not reach HexSOC backend: {exc.reason}") from exc


def send_heartbeat(backend_url: str, api_key: str) -> dict[str, Any]:
    """Notify HexSOC that this collector is online."""
    return post_json(f"{backend_url}/api/collectors/heartbeat", api_key)


def send_windows_events(backend_url: str, api_key: str, events_payload: dict[str, Any], auto_detect: bool) -> dict[str, Any]:
    """Send Windows/Sysmon events through the collector ingestion endpoint."""
    auto_detect_value = "true" if auto_detect else "false"
    url = f"{backend_url}/api/collectors/ingest/windows-events/bulk?auto_detect={auto_detect_value}"
    return post_json(url, api_key, events_payload)


def iter_event_batches(events_payload: dict[str, Any], batch_size: int) -> list[dict[str, Any]]:
    """Split an events payload into collector-friendly batches."""
    events = events_payload.get("events")
    if not isinstance(events, list):
        return [events_payload]
    size = max(1, batch_size)
    return [{"events": events[index : index + size]} for index in range(0, len(events), size)]


def print_summary(label: str, payload: dict[str, Any]) -> None:
    """Print stable, operator-friendly response summaries."""
    print(f"\n{label}")
    print("-" * len(label))
    for key in ("collector_name", "collector_type", "status", "last_seen_at"):
        if key in payload:
            print(f"{key}: {payload.get(key)}")
    for key in ("received", "ingested", "skipped", "assets_created", "alerts_created"):
        if key in payload:
            print(f"{key}: {payload.get(key)}")
    detection = payload.get("detection_summary")
    if detection:
        if "alerts_created" in detection:
            print(f"alerts_created: {detection.get('alerts_created')}")
        print("detection_summary:")
        for key, value in detection.items():
            print(f"  {key}: {value}")
    errors = payload.get("validation_errors") or []
    if errors:
        print("validation_errors:")
        for item in errors:
            print(f"  - {item}")


def parse_args() -> argparse.Namespace:
    """Parse HexSOC Agent CLI flags."""
    parser = argparse.ArgumentParser(description="HexSOC Agent telemetry sender")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="Path to config JSON")
    parser.add_argument("--once", action="store_true", help="Send one telemetry batch and exit")
    parser.add_argument("--heartbeat-only", action="store_true", help="Only send collector heartbeat")
    parser.add_argument("--events-file", help="Path to Windows/Sysmon JSON events file")
    return parser.parse_args()


def main() -> int:
    """Agent entrypoint."""
    args = parse_args()
    config_path = Path(args.config)
    config = load_json_file(config_path)

    backend_url = normalize_backend_url(str(config.get("backend_url", "")))
    api_key = os.getenv("COLLECTOR_API_KEY") or str(config.get("collector_api_key", ""))
    auto_detect = bool(config.get("auto_detect", True))
    batch_size = int(config.get("batch_size", 10) or 10)

    if not backend_url:
        print("backend_url is required in config.", file=sys.stderr)
        return 2
    if not api_key or api_key == "PUT_COLLECTOR_KEY_HERE":
        print("collector_api_key is required in config or COLLECTOR_API_KEY.", file=sys.stderr)
        return 2

    heartbeat = send_heartbeat(backend_url, api_key)
    print_summary("Heartbeat", heartbeat)

    if args.heartbeat_only:
        return 0

    if not args.once:
        print("Prototype agent supports one-shot mode only. Use --once to send sample telemetry.", file=sys.stderr)
        return 2

    events_file = Path(args.events_file or config.get("events_file") or config_path.parent / DEFAULT_EVENTS_FILE)
    events_payload = load_json_file(events_file)
    for index, batch in enumerate(iter_event_batches(events_payload, batch_size), start=1):
        ingestion = send_windows_events(backend_url, api_key, batch, auto_detect=auto_detect)
        print_summary(f"Ingestion batch {index}", ingestion)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
