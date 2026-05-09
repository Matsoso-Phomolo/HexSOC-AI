"""Lightweight HexSOC Agent prototype.

This prototype sends Windows/Sysmon telemetry to HexSOC AI through collector
API keys. It intentionally avoids privileged host collection until the agent
contract is stable.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import sys
import time
from pathlib import Path
from typing import Any
from urllib import error, request


DEFAULT_CONFIG = "config.json"
DEFAULT_EVENTS_FILE = "sample_windows_events.json"
DEFAULT_AGENT_VERSION = "0.1.0"
DEFAULT_INTERVAL_SECONDS = 60
DEFAULT_RETRY_DELAY_SECONDS = 10


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


def now_label() -> str:
    """Return a compact local timestamp for operator logs."""
    return time.strftime("%H:%M:%S")


def log_line(message: str) -> None:
    """Print one concise runtime log line."""
    print(f"[{now_label()}] {message}", flush=True)


def print_loop_header(config: dict[str, Any], backend_url: str, interval: int, mode: str) -> None:
    """Print a readable startup banner for service mode."""
    host_name = str(config.get("host_name") or socket.gethostname())
    print("=" * 48)
    print("HEXSOC AI AGENT LOOP")
    print("=" * 48)
    print(f"collector: {host_name}")
    print(f"mode: {mode}")
    print(f"interval: {interval}s")
    print(f"backend: {backend_url}")
    print("=" * 48, flush=True)


def build_heartbeat_payload(config: dict[str, Any], last_event_count: int = 0, last_error: str | None = None) -> dict[str, Any]:
    """Build a host health payload for HexSOC collector monitoring."""
    return {
        "agent_version": str(config.get("agent_version") or DEFAULT_AGENT_VERSION),
        "host_name": str(config.get("host_name") or socket.gethostname()),
        "os_name": str(config.get("os_name") or platform.system() or "unknown"),
        "os_version": str(config.get("os_version") or platform.platform()),
        "last_event_count": last_event_count,
        "last_error": last_error,
    }


def send_heartbeat(
    backend_url: str,
    api_key: str,
    config: dict[str, Any],
    last_event_count: int = 0,
    last_error: str | None = None,
) -> dict[str, Any]:
    """Notify HexSOC that this collector is online."""
    return post_json(
        f"{backend_url}/api/collectors/heartbeat",
        api_key,
        build_heartbeat_payload(config, last_event_count=last_event_count, last_error=last_error),
    )


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
    for key in ("collector_name", "collector_type", "status", "health_status", "last_seen_at", "last_heartbeat_at", "heartbeat_count"):
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


def summarize_ingestion(index: int, ingestion: dict[str, Any]) -> None:
    """Print concise ingestion batch results."""
    ingested = int(ingestion.get("ingested", 0) or 0)
    skipped = int(ingestion.get("skipped", 0) or 0)
    detection = ingestion.get("detection_summary") or {}
    alerts_created = int(detection.get("alerts_created", 0) or 0)
    log_line(f"batch {index} ingested ({ingested} events, {skipped} skipped)")
    if alerts_created:
        log_line(f"alerts created: {alerts_created}")


def parse_args() -> argparse.Namespace:
    """Parse HexSOC Agent CLI flags."""
    parser = argparse.ArgumentParser(description="HexSOC Agent telemetry sender")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="Path to config JSON")
    parser.add_argument("--once", action="store_true", help="Send one telemetry batch and exit")
    parser.add_argument("--heartbeat-only", action="store_true", help="Only send collector heartbeat")
    parser.add_argument("--heartbeat-loop", action="store_true", help="Run continuous heartbeats only")
    parser.add_argument("--telemetry-only", action="store_true", help="Run continuous telemetry ingestion without heartbeat")
    parser.add_argument("--events-file", help="Path to Windows/Sysmon JSON events file")
    parser.add_argument("--interval", type=int, help="Heartbeat interval in seconds for continuous mode")
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
    interval = int(
        args.interval
        or config.get("telemetry_interval_seconds")
        or config.get("heartbeat_interval_seconds")
        or DEFAULT_INTERVAL_SECONDS
    )
    retry_delay = int(config.get("retry_delay_seconds", DEFAULT_RETRY_DELAY_SECONDS) or DEFAULT_RETRY_DELAY_SECONDS)

    if not backend_url:
        print("backend_url is required in config.", file=sys.stderr)
        return 2
    if not api_key or api_key == "PUT_COLLECTOR_KEY_HERE":
        print("collector_api_key is required in config or COLLECTOR_API_KEY.", file=sys.stderr)
        return 2

    if args.heartbeat_only:
        heartbeat = send_heartbeat(backend_url, api_key, config)
        print_summary("Heartbeat", heartbeat)
        return 0

    if args.once:
        events_file = Path(args.events_file or config.get("events_file") or config_path.parent / DEFAULT_EVENTS_FILE)
        events_payload = load_json_file(events_file)
        heartbeat = send_heartbeat(backend_url, api_key, config)
        print_summary("Heartbeat", heartbeat)
        total_ingested = send_sample_batches(backend_url, api_key, events_payload, batch_size, auto_detect)
        heartbeat = send_heartbeat(backend_url, api_key, config, last_event_count=total_ingested)
        print_summary("Post-ingestion heartbeat", heartbeat)
        return 0

    if args.heartbeat_loop and args.telemetry_only:
        print("--heartbeat-loop and --telemetry-only cannot be used together.", file=sys.stderr)
        return 2

    events_payload = {}
    if not args.heartbeat_loop:
        events_file = Path(args.events_file or config.get("events_file") or config_path.parent / DEFAULT_EVENTS_FILE)
        events_payload = load_json_file(events_file)

    mode = "heartbeat-only" if args.heartbeat_loop else "telemetry-only" if args.telemetry_only else "heartbeat + telemetry"
    print_loop_header(config, backend_url, interval, mode)
    run_service_loop(
        backend_url=backend_url,
        api_key=api_key,
        config=config,
        events_payload=events_payload,
        batch_size=batch_size,
        auto_detect=auto_detect,
        interval=interval,
        retry_delay=retry_delay,
        heartbeat_enabled=not args.telemetry_only,
        telemetry_enabled=not args.heartbeat_loop,
    )
    return 0


def send_sample_batches(
    backend_url: str,
    api_key: str,
    events_payload: dict[str, Any],
    batch_size: int,
    auto_detect: bool,
) -> int:
    """Send sample event batches and return total successfully ingested events."""
    total_ingested = 0
    for index, batch in enumerate(iter_event_batches(events_payload, batch_size), start=1):
        ingestion = send_windows_events(backend_url, api_key, batch, auto_detect=auto_detect)
        total_ingested += int(ingestion.get("ingested", 0) or 0)
        print_summary(f"Ingestion batch {index}", ingestion)
    return total_ingested


def send_sample_batches_compact(
    backend_url: str,
    api_key: str,
    events_payload: dict[str, Any],
    batch_size: int,
    auto_detect: bool,
) -> int:
    """Send sample batches with concise service-loop logging."""
    total_ingested = 0
    total_alerts = 0
    for index, batch in enumerate(iter_event_batches(events_payload, batch_size), start=1):
        ingestion = send_windows_events(backend_url, api_key, batch, auto_detect=auto_detect)
        total_ingested += int(ingestion.get("ingested", 0) or 0)
        detection = ingestion.get("detection_summary") or {}
        total_alerts += int(detection.get("alerts_created", 0) or 0)
        summarize_ingestion(index, ingestion)
    if total_alerts:
        log_line(f"cycle alerts created: {total_alerts}")
    return total_ingested


def run_service_loop(
    *,
    backend_url: str,
    api_key: str,
    config: dict[str, Any],
    events_payload: dict[str, Any],
    batch_size: int,
    auto_detect: bool,
    interval: int,
    retry_delay: int,
    heartbeat_enabled: bool,
    telemetry_enabled: bool,
) -> None:
    """Run the long-lived agent service loop."""
    last_event_count = 0
    last_error = None
    sleep_seconds = max(5, interval)
    retry_seconds = max(1, retry_delay)

    try:
        while True:
            try:
                if heartbeat_enabled:
                    send_heartbeat(backend_url, api_key, config, last_event_count=last_event_count, last_error=last_error)
                    log_line("heartbeat sent")

                if telemetry_enabled:
                    last_event_count = send_sample_batches_compact(
                        backend_url,
                        api_key,
                        events_payload,
                        batch_size,
                        auto_detect,
                    )

                if heartbeat_enabled and telemetry_enabled:
                    send_heartbeat(backend_url, api_key, config, last_event_count=last_event_count)
                    log_line("post-ingestion heartbeat sent")

                last_error = None
                log_line(f"sleeping {sleep_seconds}s")
                time.sleep(sleep_seconds)
            except RuntimeError as exc:
                last_error = str(exc)
                log_line(f"network error - retrying next cycle in {retry_seconds}s")
                time.sleep(retry_seconds)
    except KeyboardInterrupt:
        print("\nHexSOC agent shutting down gracefully", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
