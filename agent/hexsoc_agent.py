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

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - dependency is optional at runtime
    load_dotenv = None

from agent_state import (
    add_sent_fingerprints,
    filter_new_events,
    get_windows_event_cursors,
    increment_counters,
    load_state,
    normalize_path as normalize_state_path,
    reset_windows_event_cursors,
    save_state,
    update_last_run,
    update_windows_event_cursors,
)
from offline_queue import (
    clear_queue,
    dead_letter_path_for,
    dead_letter_size,
    enqueue,
    flush_queue,
    normalize_path,
    queue_size,
)
from utils.cli_output import (
    print_error_block,
    print_info_block,
    print_success_block,
    print_warning_block,
)
from windows_event_reader import DEFAULT_CHANNELS, read_windows_events, validate_channel, validate_sysmon


DEFAULT_ENVIRONMENT = "local"
DEFAULT_EVENTS_FILE = "sample_windows_events.json"
DEFAULT_AGENT_VERSION = "0.1.0"
DEFAULT_INTERVAL_SECONDS = 60
DEFAULT_RETRY_DELAY_SECONDS = 10
DEFAULT_MAX_RETRY_ATTEMPTS = 10
DEFAULT_FINGERPRINT_HISTORY_LIMIT = 5000
WINDOWS_BULK_ENDPOINT = "/api/collectors/ingest/windows-events/bulk"
NORMALIZED_BULK_ENDPOINT = "/api/collectors/ingest/events/bulk"
ENV_CONFIG_FILES = {
    "local": "config.local.json",
    "staging": "config.staging.json",
    "production": "config.production.json",
}
AGENT_DIR = Path(__file__).resolve().parent
ENV_OVERRIDES = {
    "HEXSOC_BACKEND_URL": "backend_url",
    "HEXSOC_API_KEY": "collector_api_key",
    "HEXSOC_AGENT_NAME": "agent_name",
}
LEGACY_ENV_OVERRIDES = {
    "COLLECTOR_API_KEY": "collector_api_key",
}
SECRET_FIELDS = {"collector_api_key"}
LOG_FILE_PATH: Path | None = None


def configure_log_file(path: str | None) -> None:
    """Configure optional runtime file logging."""
    global LOG_FILE_PATH
    if not path:
        LOG_FILE_PATH = None
        return
    log_path = Path(path)
    if not log_path.is_absolute():
        log_path = AGENT_DIR.parent / log_path
    log_path.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE_PATH = log_path
    write_log_file("logging_configured")


def write_log_file(message: str) -> None:
    """Append a sanitized message to the configured log file."""
    if LOG_FILE_PATH is None:
        return
    with LOG_FILE_PATH.open("a", encoding="utf-8") as file:
        file.write(f"{utc_runtime_label()} {message}\n")


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


def is_local_backend_url(value: str) -> bool:
    """Return whether a backend URL points to a local development host."""
    normalized = value.lower()
    return "localhost" in normalized or "127.0.0.1" in normalized or "[::1]" in normalized


def resolve_environment(args: argparse.Namespace) -> str:
    """Resolve effective environment from CLI, environment, or default."""
    environment = (args.env or os.getenv("HEXSOC_ENV") or DEFAULT_ENVIRONMENT).lower()
    if environment not in ENV_CONFIG_FILES:
        raise ValueError(f"Unsupported environment: {environment}")
    return environment


def resolve_config_path(args: argparse.Namespace, environment: str) -> Path:
    """Resolve config path and effective environment."""
    if args.config:
        return Path(args.config)
    return AGENT_DIR / ENV_CONFIG_FILES[environment]


def env_has_runtime_config() -> bool:
    """Return whether environment variables can provide required runtime config."""
    return bool(os.getenv("HEXSOC_BACKEND_URL") and (os.getenv("HEXSOC_API_KEY") or os.getenv("COLLECTOR_API_KEY")))


def load_local_dotenv(environment: str) -> bool:
    """Load .env for local development only."""
    dotenv_path = AGENT_DIR / ".env"
    if environment == "production" and dotenv_path.exists():
        print("WARNING: .env exists but production mode does not load local dotenv files.", file=sys.stderr)
        return False
    if environment != "local" or not dotenv_path.exists():
        return False
    if load_dotenv is None:
        print("WARNING: python-dotenv is not installed; .env was not loaded.", file=sys.stderr)
        return False
    load_dotenv(dotenv_path=dotenv_path, override=False)
    return True


def apply_env_overrides(config: dict[str, Any]) -> tuple[dict[str, Any], set[str]]:
    """Apply supported OS environment overrides to JSON config."""
    active = dict(config)
    overridden: set[str] = set()
    for env_name, config_key in LEGACY_ENV_OVERRIDES.items():
        value = os.getenv(env_name)
        if value is not None and value != "" and not os.getenv("HEXSOC_API_KEY"):
            active[config_key] = value
            overridden.add(config_key)
    for env_name, config_key in ENV_OVERRIDES.items():
        value = os.getenv(env_name)
        if value is not None and value != "":
            active[config_key] = value
            overridden.add(config_key)
            if config_key == "agent_name":
                active["host_name"] = value
                overridden.add("host_name")
    return active, overridden


def config_source(overridden_keys: set[str], config: dict[str, Any]) -> str:
    """Return FILE, ENVIRONMENT_VARIABLES, or MIXED."""
    if overridden_keys and not config:
        return "ENVIRONMENT_VARIABLES"
    if overridden_keys:
        return "MIXED"
    return "FILE"


def mask_secret(value: str | None) -> str:
    """Mask a secret for logs while keeping enough prefix for operator matching."""
    if not value:
        return "not configured"
    visible = min(16, len(value))
    return f"{value[:visible]}****************"


def sanitized_config(config: dict[str, Any], environment: str, source: str) -> dict[str, Any]:
    """Return runtime config safe for logs and support output."""
    safe = {}
    for key, value in config.items():
        safe[key] = mask_secret(str(value)) if key in SECRET_FIELDS else value
    safe["environment"] = environment
    safe["config_source"] = source
    return safe


def print_runtime_summary(
    *,
    environment: str,
    backend_url: str,
    mode: str,
    interval: int,
    source: str,
    api_key: str,
) -> None:
    """Print a sanitized runtime summary for operators."""
    print_success_block(
        "HEXSOC AI DRY RUN SUMMARY",
        [
            ("Timestamp", utc_runtime_label()),
            ("Environment", environment.upper()),
            ("Backend", backend_url),
            ("Mode", mode),
            ("Interval", f"{interval}s"),
            ("Config source", source),
            ("API key", mask_secret(api_key)),
            ("Status", "SUCCESS"),
        ],
    )


def display_path(path: str) -> str:
    """Return a compact repo-relative queue path for CLI output."""
    resolved = normalize_path(path)
    try:
        return resolved.relative_to(AGENT_DIR.parent).as_posix()
    except ValueError:
        return str(resolved)


def display_state_path(path: str) -> str:
    """Return compact repo-relative state path for CLI output."""
    resolved = normalize_state_path(path)
    try:
        return resolved.relative_to(AGENT_DIR.parent).as_posix()
    except ValueError:
        return str(resolved)


def status_for_queue(pending: int, dead_lettered: int) -> str:
    """Return a high-level queue health label."""
    if dead_lettered:
        return "WARNING"
    if pending:
        return "PENDING"
    return "HEALTHY"


def is_clear_queue_confirmation(value: str) -> bool:
    """Return whether a queue-clear confirmation is affirmative."""
    return value.strip().lower() in {"yes", "y"}


def print_clear_cancelled() -> None:
    """Print a structured cancellation summary."""
    print_error_block(
        "HEXSOC AI QUEUE CLEAR",
        [
            ("Status", "CANCELLED"),
            ("Reason", "Confirmation rejected by user"),
        ],
    )


def print_state_status(environment: str, state_path: str) -> None:
    """Print structured agent state counters."""
    state = load_state(state_path)
    fingerprints = state.get("sent_event_fingerprints") or []
    print_info_block(
        "HEXSOC AI AGENT STATE",
        [
            ("Timestamp", utc_runtime_label()),
            ("Environment", environment.upper()),
            ("State path", display_state_path(state_path)),
            ("Last run", state.get("last_run_at") or "never"),
            ("Total events sent", state.get("total_events_sent", 0)),
            ("Total batches sent", state.get("total_batches_sent", 0)),
            ("Duplicates skipped", state.get("total_duplicates_skipped", 0)),
            ("Fingerprint count", len(fingerprints) if isinstance(fingerprints, list) else 0),
            ("Status", "HEALTHY"),
        ],
    )


def print_reset_state_cancelled() -> None:
    """Print structured state reset cancellation."""
    print_error_block(
        "HEXSOC AI STATE RESET",
        [
            ("Status", "CANCELLED"),
            ("Reason", "Confirmation rejected by user"),
        ],
    )


def print_reset_state_success(environment: str, state_path: str, previous_count: int) -> None:
    """Print structured state reset success."""
    print_success_block(
        "HEXSOC AI STATE RESET",
        [
            ("Timestamp", utc_runtime_label()),
            ("Environment", environment.upper()),
            ("State path", display_state_path(state_path)),
            ("Fingerprints cleared", previous_count),
            ("Status", "SUCCESS"),
        ],
    )


def print_windows_cursor_status(environment: str, state_path: str, channels: list[str]) -> None:
    """Print Windows Event Log cursor state."""
    state = load_state(state_path)
    cursors = get_windows_event_cursors(state)
    fields: list[tuple[str, Any]] = [
        ("Timestamp", utc_runtime_label()),
        ("Environment", environment.upper()),
        ("State path", display_state_path(state_path)),
    ]
    for channel in channels:
        fields.append((channel, cursors.get(channel, 0)))
    fields.append(("Status", "HEALTHY"))
    print_info_block("HEXSOC AI WINDOWS EVENT CURSORS", fields)


def print_reset_windows_cursors_success(environment: str, state_path: str, previous_count: int) -> None:
    """Print Windows cursor reset summary."""
    print_success_block(
        "HEXSOC AI WINDOWS CURSOR RESET",
        [
            ("Timestamp", utc_runtime_label()),
            ("Environment", environment.upper()),
            ("State path", display_state_path(state_path)),
            ("Cursors cleared", previous_count),
            ("Status", "SUCCESS"),
        ],
    )


def print_windows_cursor_reset_cancelled() -> None:
    """Print Windows cursor reset cancellation."""
    print_error_block(
        "HEXSOC AI WINDOWS CURSOR RESET",
        [
            ("Status", "CANCELLED"),
            ("Reason", "Confirmation rejected by user"),
        ],
    )


def print_windows_channel_validation(result: dict[str, Any]) -> None:
    """Print Windows channel validation result."""
    success = bool(result.get("success"))
    fields = [
        ("Timestamp", utc_runtime_label()),
        ("Channel", result.get("channel")),
        ("Channel exists", result.get("exists")),
        ("Query", result.get("query")),
        ("Query flags", result.get("flags")),
        ("Sample records", result.get("sample_record_count")),
        ("First record ID", result.get("first_record_id") or "none"),
        ("Status", "SUCCESS" if success else "FAILED"),
    ]
    if result.get("error"):
        fields.append(("Error", result.get("error")))
    if success:
        print_success_block("HEXSOC AI WINDOWS CHANNEL VALIDATION", fields)
    else:
        print_error_block("HEXSOC AI WINDOWS CHANNEL VALIDATION", fields)


def print_sysmon_validation(result: dict[str, Any]) -> None:
    """Print Sysmon validation result."""
    status = str(result.get("status") or "WARNING")
    fields = [
        ("Timestamp", utc_runtime_label()),
        ("Sysmon installed", result.get("sysmon_installed")),
        ("Channel available", result.get("channel_available")),
        ("Sample events", result.get("sample_event_count")),
        ("Latest EventRecordID", result.get("latest_record_id") or "none"),
        ("Status", status),
    ]
    if result.get("error"):
        fields.append(("Error", result.get("error")))
    if status == "SUCCESS":
        print_success_block("HEXSOC AI SYSMON VALIDATION", fields)
    else:
        print_warning_block("HEXSOC AI SYSMON VALIDATION", fields)


def print_windows_debug(debug_records: list[dict[str, Any]]) -> None:
    """Print Windows Event Log query debug records."""
    for record in debug_records:
        success = bool(record.get("success"))
        fields = [
            ("Timestamp", utc_runtime_label()),
            ("Channel", record.get("channel")),
            ("Query", record.get("query")),
            ("Query flags", record.get("flags")),
            ("Event count", record.get("event_count")),
            ("First record ID", record.get("first_record_id") or "none"),
            ("Status", "SUCCESS" if success else "FAILED"),
        ]
        if record.get("error"):
            fields.append(("Error", record.get("error")))
        if success:
            print_info_block("HEXSOC AI WINDOWS EVENT DEBUG", fields)
        else:
            print_warning_block("HEXSOC AI WINDOWS EVENT DEBUG", fields)


def warn_environment_safety(environment: str, backend_url: str) -> None:
    """Print environment/backend mismatch warnings without blocking startup."""
    is_local = is_local_backend_url(backend_url)
    if environment == "production" and is_local:
        print("WARNING: production environment is configured with a localhost backend.", file=sys.stderr)
    if environment == "local" and not is_local:
        print("WARNING: local environment is configured with a public backend URL.", file=sys.stderr)


def validate_runtime_config(environment: str, backend_url: str, api_key: str) -> list[str]:
    """Validate runtime config and return blocking errors."""
    errors: list[str] = []
    if not backend_url:
        errors.append("backend_url is required.")
    if not api_key or api_key.startswith("PUT_"):
        errors.append("collector_api_key is required in config or HEXSOC_API_KEY.")
    if environment == "production":
        if is_local_backend_url(backend_url):
            errors.append("production cannot use localhost backend_url.")
        if backend_url and not backend_url.lower().startswith("https://"):
            errors.append("production backend_url must use https.")
    return errors


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


def utc_runtime_label() -> str:
    """Return a stable UTC timestamp for command summaries."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def log_line(message: str) -> None:
    """Print one concise runtime log line."""
    print(f"[{now_label()}] {message}", flush=True)
    write_log_file(message)


def print_loop_header(
    config: dict[str, Any],
    backend_url: str,
    interval: int,
    mode: str,
    environment: str,
    source: str,
) -> None:
    """Print a readable startup banner for service mode."""
    host_name = str(config.get("host_name") or socket.gethostname())
    print("=" * 48)
    print("HEXSOC AI AGENT LOOP")
    print("=" * 48)
    print(f"ENVIRONMENT: {environment.upper()}")
    print(f"CONFIG SOURCE: {source}")
    print(f"API KEY: {mask_secret(str(config.get('collector_api_key') or ''))}")
    print(f"collector: {host_name}")
    print(f"mode: {mode}")
    print(f"interval: {interval}s")
    print(f"backend: {backend_url}")
    print("=" * 48, flush=True)
    write_log_file(
        "agent_start "
        f"environment={environment.upper()} mode={mode} interval={interval}s "
        f"backend={backend_url} collector={host_name}"
    )


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
    endpoint = windows_events_endpoint(auto_detect)
    url = f"{backend_url}{endpoint}"
    return post_json(url, api_key, events_payload)


def send_normalized_events(backend_url: str, api_key: str, events_payload: dict[str, Any], auto_detect: bool) -> dict[str, Any]:
    """Send normalized events through the collector ingestion endpoint."""
    auto_detect_value = "true" if auto_detect else "false"
    url = f"{backend_url}{NORMALIZED_BULK_ENDPOINT}?auto_detect={auto_detect_value}"
    return post_json(url, api_key, events_payload)


def windows_events_endpoint(auto_detect: bool) -> str:
    """Return the collector Windows/Sysmon bulk endpoint."""
    auto_detect_value = "true" if auto_detect else "false"
    return f"{WINDOWS_BULK_ENDPOINT}?auto_detect={auto_detect_value}"


def normalized_events_endpoint(auto_detect: bool) -> str:
    """Return the collector normalized events bulk endpoint."""
    auto_detect_value = "true" if auto_detect else "false"
    return f"{NORMALIZED_BULK_ENDPOINT}?auto_detect={auto_detect_value}"


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
    parser.add_argument("--config", help="Path to config JSON")
    parser.add_argument("--env", choices=sorted(ENV_CONFIG_FILES), help="Agent environment")
    parser.add_argument("--once", action="store_true", help="Send one telemetry batch and exit")
    parser.add_argument("--heartbeat-only", action="store_true", help="Only send collector heartbeat")
    parser.add_argument("--heartbeat-loop", action="store_true", help="Run continuous heartbeats only")
    parser.add_argument("--telemetry-only", action="store_true", help="Run continuous telemetry ingestion without heartbeat")
    parser.add_argument("--events-file", help="Path to Windows/Sysmon JSON events file")
    parser.add_argument("--interval", type=int, help="Heartbeat interval in seconds for continuous mode")
    parser.add_argument("--dry-run", action="store_true", help="Validate config without sending telemetry")
    parser.add_argument("--show-config", action="store_true", help="Print sanitized active runtime config")
    parser.add_argument("--flush-queue", action="store_true", help="Flush queued telemetry and exit")
    parser.add_argument("--queue-status", action="store_true", help="Print queue and dead-letter counts")
    parser.add_argument("--clear-queue", action="store_true", help="Clear pending and dead-letter queue files")
    parser.add_argument("--state-status", action="store_true", help="Print agent state and duplicate prevention counters")
    parser.add_argument("--reset-state", action="store_true", help="Reset event cursor and deduplication state")
    parser.add_argument("--windows-events-once", action="store_true", help="Read Windows Event Logs once and ingest new events")
    parser.add_argument("--windows-cursor-status", action="store_true", help="Print Windows Event Log cursor state")
    parser.add_argument("--reset-windows-cursors", action="store_true", help="Reset Windows Event Log cursors")
    parser.add_argument("--windows-debug", action="store_true", help="Print Windows Event Log query debug details")
    parser.add_argument("--validate-windows-channel", action="append", default=[], help="Validate a Windows Event Log channel query")
    parser.add_argument("--validate-sysmon", action="store_true", help="Validate Sysmon service and Operational channel")
    parser.add_argument("--yes", action="store_true", help="Confirm destructive queue operations")
    parser.add_argument("--log-file", help="Write runtime service logs to this file")
    return parser.parse_args()


def print_queue_status(environment: str, backend_url: str, queue_path: str, dead_letter_path: str) -> None:
    """Print structured pending and dead-letter queue counts."""
    pending = queue_size(queue_path)
    dead_lettered = dead_letter_size(dead_letter_path)
    status = status_for_queue(pending, dead_lettered)
    fields = [
        ("Timestamp", utc_runtime_label()),
        ("Environment", environment.upper()),
        ("Backend", backend_url or "not configured"),
        ("Queue path", display_path(queue_path)),
        ("Dead-letter path", display_path(dead_letter_path)),
        ("Pending items", pending),
        ("Dead-letter items", dead_lettered),
        ("Status", status),
    ]
    if status == "WARNING":
        print_warning_block("HEXSOC AI OFFLINE QUEUE STATUS", fields)
    else:
        print_info_block("HEXSOC AI OFFLINE QUEUE STATUS", fields)


def flush_agent_queue(
    backend_url: str,
    api_key: str,
    queue_path: str,
    dead_letter_path: str,
    max_retry_attempts: int,
) -> dict[str, int]:
    """Flush queued telemetry and return queue summary."""
    return flush_queue(
        backend_url=backend_url,
        api_key=api_key,
        queue_path=queue_path,
        dead_letter_path=dead_letter_path,
        max_retry_attempts=max_retry_attempts,
    )


def print_flush_summary(environment: str, summary: dict[str, int]) -> None:
    """Print structured offline queue flush results."""
    failed = int(summary.get("failed", 0) or 0)
    dead_lettered = int(summary.get("dead_lettered", 0) or 0)
    status = "SUCCESS" if failed == 0 and dead_lettered == 0 else "WARNING"
    fields = [
        ("Timestamp", utc_runtime_label()),
        ("Environment", environment.upper()),
        ("Pending before", summary.get("pending_before", 0)),
        ("Flushed", summary.get("flushed", 0)),
        ("Failed", failed),
    ]
    if dead_lettered:
        fields.append(("Dead-lettered", dead_lettered))
    fields.extend(
        [
            ("Pending after", summary.get("pending_after", 0)),
            ("Status", status),
        ]
    )
    message = None
    if dead_lettered:
        message = f"WARNING: moved {dead_lettered} item to dead-letter queue"
    if status == "SUCCESS":
        print_success_block("HEXSOC AI QUEUE FLUSH", fields)
    else:
        print_warning_block("HEXSOC AI QUEUE FLUSH", fields, message=message)


def print_show_config_summary(
    environment: str,
    backend_url: str,
    mode: str,
    interval: int,
    source: str,
    config: dict[str, Any],
) -> None:
    """Print sanitized runtime config in a readable support format."""
    safe = sanitized_config(config, environment, source)
    fields = [
        ("Timestamp", utc_runtime_label()),
        ("Environment", environment.upper()),
        ("Backend", backend_url or "not configured"),
        ("Mode", mode),
        ("Interval", f"{interval}s"),
        ("Config source", source),
        ("API key", safe.get("collector_api_key", "not configured")),
    ]
    for key in sorted(safe):
        if key in {"backend_url", "collector_api_key", "environment", "config_source"}:
            continue
        fields.append((key, safe[key]))
    print_info_block("HEXSOC AI RUNTIME CONFIG", fields)


def main() -> int:
    """Agent entrypoint."""
    args = parse_args()
    configure_log_file(args.log_file)
    try:
        environment = resolve_environment(args)
        load_local_dotenv(environment)
        config_path = resolve_config_path(args, environment)
        try:
            config = load_json_file(config_path)
        except FileNotFoundError:
            if not env_has_runtime_config():
                raise
            config = {}
        except json.JSONDecodeError:
            if not (config_path.exists() and config_path.stat().st_size == 0 and env_has_runtime_config()):
                raise
            config = {}
        active_config, overridden_keys = apply_env_overrides(config)
        source = config_source(overridden_keys, config)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Could not load agent config: {exc}", file=sys.stderr)
        return 2

    backend_url = normalize_backend_url(str(active_config.get("backend_url", "")))
    api_key = str(active_config.get("collector_api_key", ""))
    auto_detect = bool(active_config.get("auto_detect", True))
    batch_size = int(active_config.get("batch_size", 10) or 10)
    queue_enabled = bool(active_config.get("offline_queue_enabled", True))
    queue_path = str(active_config.get("offline_queue_path") or "data/offline_queue.jsonl")
    dead_letter_path = str(active_config.get("dead_letter_queue_path") or dead_letter_path_for(queue_path))
    max_retry_attempts = int(active_config.get("max_retry_attempts", DEFAULT_MAX_RETRY_ATTEMPTS) or DEFAULT_MAX_RETRY_ATTEMPTS)
    state_path = str(active_config.get("agent_state_path") or "data/agent_state.json")
    deduplicate_events = bool(active_config.get("deduplicate_events", True))
    fingerprint_history_limit = int(
        active_config.get("fingerprint_history_limit", DEFAULT_FINGERPRINT_HISTORY_LIMIT) or DEFAULT_FINGERPRINT_HISTORY_LIMIT
    )
    agent_mode = str(active_config.get("mode") or "windows_sysmon_sample")
    windows_event_channels = list(active_config.get("windows_event_channels") or DEFAULT_CHANNELS)
    windows_event_batch_size = int(active_config.get("windows_event_batch_size", 50) or 50)
    windows_event_max_per_cycle = int(active_config.get("windows_event_max_per_cycle", 200) or 200)
    windows_event_start_position = str(active_config.get("windows_event_start_position") or "latest")
    interval = int(
        args.interval
        or active_config.get("telemetry_interval_seconds")
        or active_config.get("heartbeat_interval_seconds")
        or DEFAULT_INTERVAL_SECONDS
    )
    retry_delay = int(active_config.get("retry_delay_seconds", DEFAULT_RETRY_DELAY_SECONDS) or DEFAULT_RETRY_DELAY_SECONDS)
    if args.heartbeat_loop and args.telemetry_only:
        print("--heartbeat-loop and --telemetry-only cannot be used together.", file=sys.stderr)
        return 2

    if args.queue_status:
        print_queue_status(environment, backend_url, queue_path, dead_letter_path)
        return 0

    if args.state_status:
        print_state_status(environment, state_path)
        return 0

    if args.windows_cursor_status:
        print_windows_cursor_status(environment, state_path, windows_event_channels)
        return 0

    if args.validate_windows_channel:
        for channel in args.validate_windows_channel:
            print_windows_channel_validation(validate_channel(channel))
        return 0

    if args.validate_sysmon:
        print_sysmon_validation(validate_sysmon())
        return 0

    if args.clear_queue:
        if not args.yes:
            print_warning_block(
                "HEXSOC AI QUEUE CLEAR",
                [
                    ("Environment", environment.upper()),
                    ("Queue path", display_path(queue_path)),
                    ("Dead-letter path", display_path(dead_letter_path)),
                    ("Status", "WARNING"),
                ],
                message="Type YES to continue",
            )
            confirmation = input("Type YES to continue: ")
            if not is_clear_queue_confirmation(confirmation):
                print_clear_cancelled()
                return 1
        pending_before = queue_size(queue_path)
        dead_letter_before = dead_letter_size(dead_letter_path)
        clear_queue(queue_path, dead_letter_path)
        print_success_block(
            "HEXSOC AI QUEUE CLEAR",
            [
                ("Timestamp", utc_runtime_label()),
                ("Environment", environment.upper()),
                ("Pending cleared", pending_before),
                ("Dead-letter cleared", dead_letter_before),
                ("Status", "SUCCESS"),
            ],
        )
        return 0

    if args.reset_state:
        state = load_state(state_path)
        previous_count = len(state.get("sent_event_fingerprints") or [])
        if not args.yes:
            print_warning_block(
                "HEXSOC AI STATE RESET",
                [
                    ("Environment", environment.upper()),
                    ("State path", display_state_path(state_path)),
                    ("Fingerprints", previous_count),
                    ("Status", "WARNING"),
                ],
                message="Resetting state may cause duplicate telemetry and alerts to be resent. Type YES to continue",
            )
            confirmation = input("Type YES to continue: ")
            if not is_clear_queue_confirmation(confirmation):
                print_reset_state_cancelled()
                return 1
        state = {
            "last_run_at": None,
            "last_event_cursor": None,
            "sent_event_fingerprints": [],
            "total_events_sent": 0,
            "total_batches_sent": 0,
            "total_duplicates_skipped": 0,
        }
        save_state(state_path, state)
        print_reset_state_success(environment, state_path, previous_count)
        return 0

    if args.reset_windows_cursors:
        state = load_state(state_path)
        previous_count = len(get_windows_event_cursors(state))
        if not args.yes:
            print_warning_block(
                "HEXSOC AI WINDOWS CURSOR RESET",
                [
                    ("Environment", environment.upper()),
                    ("State path", display_state_path(state_path)),
                    ("Cursors", previous_count),
                    ("Status", "WARNING"),
                ],
                message="Resetting cursors may cause Windows events to be replayed. Type YES to continue",
            )
            confirmation = input("Type YES to continue: ")
            if not is_clear_queue_confirmation(confirmation):
                print_windows_cursor_reset_cancelled()
                return 1
        reset_windows_event_cursors(state)
        save_state(state_path, state)
        print_reset_windows_cursors_success(environment, state_path, previous_count)
        return 0

    if args.flush_queue and queue_size(queue_path) == 0:
        print_flush_summary(
            environment,
            {
                "pending_before": 0,
                "flushed": 0,
                "failed": 0,
                "dead_lettered": 0,
                "pending_after": 0,
            },
        )
        return 0

    warn_environment_safety(environment, backend_url)
    validation_errors = validate_runtime_config(environment, backend_url, api_key)
    if validation_errors:
        for item in validation_errors:
            print(f"CONFIG ERROR: {item}", file=sys.stderr)
        return 2

    mode = "heartbeat-only" if args.heartbeat_loop or args.heartbeat_only else "telemetry-only" if args.telemetry_only else "heartbeat + telemetry"
    if args.show_config:
        print_show_config_summary(environment, backend_url, mode, interval, source, active_config)
        if not args.dry_run:
            return 0
    if args.dry_run and not args.windows_events_once:
        print_runtime_summary(
            environment=environment,
            backend_url=backend_url,
            mode=mode,
            interval=interval,
            source=source,
            api_key=api_key,
        )
        print("Dry run complete. No telemetry was sent.")
        return 0

    if args.flush_queue:
        print_flush_summary(environment, flush_agent_queue(backend_url, api_key, queue_path, dead_letter_path, max_retry_attempts))
        return 0

    if args.heartbeat_only:
        heartbeat = send_heartbeat(backend_url, api_key, active_config)
        print_summary("Heartbeat", heartbeat)
        return 0

    if args.windows_events_once:
        total_ingested = collect_and_send_windows_events(
            backend_url=backend_url,
            api_key=api_key,
            state_path=state_path,
            channels=windows_event_channels,
            batch_size=windows_event_batch_size,
            max_per_cycle=windows_event_max_per_cycle,
            start_position=windows_event_start_position,
            auto_detect=auto_detect,
            dry_run=args.dry_run,
            queue_enabled=queue_enabled,
            queue_path=queue_path,
            fingerprint_history_limit=fingerprint_history_limit,
            debug=args.windows_debug,
        )
        print(f"Windows events processed: {total_ingested}")
        return 0

    if args.once:
        if agent_mode == "windows_event_log":
            total_ingested = collect_and_send_windows_events(
                backend_url=backend_url,
                api_key=api_key,
                state_path=state_path,
                channels=windows_event_channels,
                batch_size=windows_event_batch_size,
                max_per_cycle=windows_event_max_per_cycle,
                start_position=windows_event_start_position,
                auto_detect=auto_detect,
                dry_run=False,
                queue_enabled=queue_enabled,
                queue_path=queue_path,
                fingerprint_history_limit=fingerprint_history_limit,
                debug=args.windows_debug,
            )
            print(f"Windows events processed: {total_ingested}")
            return 0
        events_file = Path(args.events_file or active_config.get("events_file") or config_path.parent / DEFAULT_EVENTS_FILE)
        events_payload = load_json_file(events_file)
        try:
            heartbeat = send_heartbeat(backend_url, api_key, active_config)
            print_summary("Heartbeat", heartbeat)
        except RuntimeError as exc:
            print(f"Heartbeat failed and was not queued: {exc}")
        if queue_enabled:
            print_flush_summary(environment, flush_agent_queue(backend_url, api_key, queue_path, dead_letter_path, max_retry_attempts))
        total_ingested = send_sample_batches(
            backend_url,
            api_key,
            events_payload,
            batch_size,
            auto_detect,
            queue_enabled=queue_enabled,
            queue_path=queue_path,
            state_path=state_path,
            deduplicate_events=deduplicate_events,
            fingerprint_history_limit=fingerprint_history_limit,
        )
        try:
            heartbeat = send_heartbeat(backend_url, api_key, active_config, last_event_count=total_ingested)
            print_summary("Post-ingestion heartbeat", heartbeat)
        except RuntimeError as exc:
            print(f"Post-ingestion heartbeat failed and was not queued: {exc}")
        return 0

    events_payload = {}
    if not args.heartbeat_loop and agent_mode != "windows_event_log":
        events_file = Path(args.events_file or active_config.get("events_file") or config_path.parent / DEFAULT_EVENTS_FILE)
        events_payload = load_json_file(events_file)

    print_loop_header(active_config, backend_url, interval, mode, environment, source)
    run_service_loop(
        backend_url=backend_url,
        api_key=api_key,
        config=active_config,
        events_payload=events_payload,
        batch_size=batch_size,
        auto_detect=auto_detect,
        interval=interval,
        retry_delay=retry_delay,
        queue_enabled=queue_enabled,
        queue_path=queue_path,
        dead_letter_path=dead_letter_path,
        max_retry_attempts=max_retry_attempts,
        state_path=state_path,
        deduplicate_events=deduplicate_events,
        fingerprint_history_limit=fingerprint_history_limit,
        debug=args.windows_debug,
        agent_mode=agent_mode,
        windows_event_channels=windows_event_channels,
        windows_event_batch_size=windows_event_batch_size,
        windows_event_max_per_cycle=windows_event_max_per_cycle,
        windows_event_start_position=windows_event_start_position,
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
    queue_enabled: bool = False,
    queue_path: str | None = None,
    state_path: str | None = None,
    deduplicate_events: bool = True,
    fingerprint_history_limit: int = DEFAULT_FINGERPRINT_HISTORY_LIMIT,
) -> int:
    """Send sample event batches and return total successfully ingested events."""
    total_ingested = 0
    state = load_state(state_path)
    duplicates_skipped = 0
    batch_payload = events_payload
    fingerprints: list[str] = []
    if deduplicate_events:
        events = events_payload.get("events")
        if isinstance(events, list):
            new_events, fingerprints, duplicates_skipped = filter_new_events(events, state)
            if duplicates_skipped:
                print(f"Skipped {duplicates_skipped} duplicate events")
                write_log_file(f"Skipped {duplicates_skipped} duplicate events")
            if not new_events:
                print("No new telemetry to send")
                write_log_file("No new telemetry to send")
                update_last_run(state)
                increment_counters(state, duplicates_skipped=duplicates_skipped)
                save_state(state_path, state)
                return 0
            batch_payload = dict(events_payload)
            batch_payload["events"] = new_events
    batches = iter_event_batches(batch_payload, batch_size)
    event_offset = 0
    for index, batch in enumerate(batches, start=1):
        batch_events = batch.get("events") if isinstance(batch.get("events"), list) else []
        batch_fingerprints = []
        if deduplicate_events and isinstance(batch_events, list):
            batch_fingerprints = [fingerprints[event_offset + idx] for idx in range(len(batch_events))]
            event_offset += len(batch_events)
        try:
            ingestion = send_windows_events(backend_url, api_key, batch, auto_detect=auto_detect)
            total_ingested += int(ingestion.get("ingested", 0) or 0)
            print_summary(f"Ingestion batch {index}", ingestion)
            if deduplicate_events:
                add_sent_fingerprints(state, batch_fingerprints, limit=fingerprint_history_limit)
            increment_counters(
                state,
                events_sent=len(batch_events) if isinstance(batch_events, list) else int(ingestion.get("ingested", 0) or 0),
                batches_sent=1,
                duplicates_skipped=duplicates_skipped if index == 1 else 0,
            )
            update_last_run(state)
            save_state(state_path, state)
        except RuntimeError as exc:
            if queue_enabled:
                enqueue(windows_events_endpoint(auto_detect), batch, reason=str(exc), queue_path=queue_path)
                print(f"Ingestion batch {index} failed and was queued for retry.")
                continue
            raise
    return total_ingested


def send_sample_batches_compact(
    backend_url: str,
    api_key: str,
    events_payload: dict[str, Any],
    batch_size: int,
    auto_detect: bool,
    queue_enabled: bool = False,
    queue_path: str | None = None,
    state_path: str | None = None,
    deduplicate_events: bool = True,
    fingerprint_history_limit: int = DEFAULT_FINGERPRINT_HISTORY_LIMIT,
) -> int:
    """Send sample batches with concise service-loop logging."""
    total_ingested = 0
    total_alerts = 0
    state = load_state(state_path)
    duplicates_skipped = 0
    batch_payload = events_payload
    fingerprints: list[str] = []
    if deduplicate_events:
        events = events_payload.get("events")
        if isinstance(events, list):
            new_events, fingerprints, duplicates_skipped = filter_new_events(events, state)
            if duplicates_skipped:
                log_line(f"Skipped {duplicates_skipped} duplicate events")
            if not new_events:
                log_line("No new telemetry to send")
                update_last_run(state)
                increment_counters(state, duplicates_skipped=duplicates_skipped)
                save_state(state_path, state)
                return 0
            batch_payload = dict(events_payload)
            batch_payload["events"] = new_events
    event_offset = 0
    for index, batch in enumerate(iter_event_batches(batch_payload, batch_size), start=1):
        batch_events = batch.get("events") if isinstance(batch.get("events"), list) else []
        batch_fingerprints = []
        if deduplicate_events and isinstance(batch_events, list):
            batch_fingerprints = [fingerprints[event_offset + idx] for idx in range(len(batch_events))]
            event_offset += len(batch_events)
        try:
            ingestion = send_windows_events(backend_url, api_key, batch, auto_detect=auto_detect)
            total_ingested += int(ingestion.get("ingested", 0) or 0)
            detection = ingestion.get("detection_summary") or {}
            total_alerts += int(detection.get("alerts_created", 0) or 0)
            summarize_ingestion(index, ingestion)
            if deduplicate_events:
                add_sent_fingerprints(state, batch_fingerprints, limit=fingerprint_history_limit)
            increment_counters(
                state,
                events_sent=len(batch_events) if isinstance(batch_events, list) else int(ingestion.get("ingested", 0) or 0),
                batches_sent=1,
                duplicates_skipped=duplicates_skipped if index == 1 else 0,
            )
            update_last_run(state)
            save_state(state_path, state)
        except RuntimeError as exc:
            if queue_enabled:
                enqueue(windows_events_endpoint(auto_detect), batch, reason=str(exc), queue_path=queue_path)
                log_line(f"batch {index} failed and was queued for retry")
                continue
            raise
    if total_alerts:
        log_line(f"cycle alerts created: {total_alerts}")
    return total_ingested


def collect_and_send_windows_events(
    *,
    backend_url: str,
    api_key: str,
    state_path: str,
    channels: list[str],
    batch_size: int,
    max_per_cycle: int,
    start_position: str,
    auto_detect: bool,
    dry_run: bool,
    queue_enabled: bool,
    queue_path: str,
    fingerprint_history_limit: int,
    debug: bool = False,
) -> int:
    """Read Windows Event Logs once and optionally ingest normalized events."""
    state = load_state(state_path)
    cursors = get_windows_event_cursors(state)
    result = read_windows_events(
        channels=channels,
        cursors=cursors,
        batch_size=batch_size,
        max_per_cycle=max_per_cycle,
        start_position=start_position,
        debug=debug,
    )
    for warning in result.get("warnings", []):
        log_line(f"WARNING: {warning}")
    if debug:
        print_windows_debug(list(result.get("debug") or []))
    events = result.get("events") if isinstance(result.get("events"), list) else []
    updated_cursors = result.get("cursors") if isinstance(result.get("cursors"), dict) else cursors

    if dry_run:
        print_info_block(
            "HEXSOC AI WINDOWS EVENT DRY RUN",
            [
                ("Timestamp", utc_runtime_label()),
                ("Events found", len(events)),
                ("Channels", ", ".join(channels)),
                ("Status", "HEALTHY" if result.get("available") else "WARNING"),
            ],
        )
        return len(events)

    if not events:
        update_windows_event_cursors(state, {str(channel): int(cursor) for channel, cursor in updated_cursors.items()})
        update_last_run(state)
        save_state(state_path, state)
        log_line("No new Windows events to send")
        return 0

    total_ingested = 0
    sent_fingerprints: list[str] = []
    for index, batch in enumerate(iter_event_batches({"events": events}, batch_size), start=1):
        try:
            ingestion = send_normalized_events(backend_url, api_key, batch, auto_detect=auto_detect)
            total_ingested += int(ingestion.get("ingested", 0) or 0)
            batch_events = batch.get("events") if isinstance(batch.get("events"), list) else []
            sent_fingerprints.extend([str((event.get("raw_payload") or {}).get("record_id") or "") for event in batch_events])
            summarize_ingestion(index, ingestion)
        except RuntimeError as exc:
            if queue_enabled:
                enqueue(normalized_events_endpoint(auto_detect), batch, reason=str(exc), queue_path=queue_path)
                log_line(f"Windows event batch {index} failed and was queued for retry")
                continue
            raise

    if total_ingested:
        update_windows_event_cursors(state, {str(channel): int(cursor) for channel, cursor in updated_cursors.items()})
        add_sent_fingerprints(state, [fingerprint for fingerprint in sent_fingerprints if fingerprint], limit=fingerprint_history_limit)
        increment_counters(state, events_sent=total_ingested, batches_sent=max(1, len(iter_event_batches({"events": events}, batch_size))))
        update_last_run(state)
        save_state(state_path, state)
        log_line(f"Ingested {total_ingested} Windows events")
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
    queue_enabled: bool,
    queue_path: str,
    dead_letter_path: str,
    max_retry_attempts: int,
    state_path: str,
    deduplicate_events: bool,
    fingerprint_history_limit: int,
    debug: bool,
    agent_mode: str,
    windows_event_channels: list[str],
    windows_event_batch_size: int,
    windows_event_max_per_cycle: int,
    windows_event_start_position: str,
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
                if queue_enabled:
                    summary = flush_agent_queue(backend_url, api_key, queue_path, dead_letter_path, max_retry_attempts)
                    if summary.get("pending_before", 0):
                        log_line(
                            "queue flush "
                            f"pending={summary.get('pending_before', 0)} "
                            f"flushed={summary.get('flushed', 0)} "
                            f"failed={summary.get('failed', 0)} "
                            f"dead_lettered={summary.get('dead_lettered', 0)}"
                        )
                if heartbeat_enabled:
                    send_heartbeat(backend_url, api_key, config, last_event_count=last_event_count, last_error=last_error)
                    log_line("heartbeat sent")

                if telemetry_enabled and agent_mode == "windows_event_log":
                    last_event_count = collect_and_send_windows_events(
                        backend_url=backend_url,
                        api_key=api_key,
                        state_path=state_path,
                        channels=windows_event_channels,
                        batch_size=windows_event_batch_size,
                        max_per_cycle=windows_event_max_per_cycle,
                        start_position=windows_event_start_position,
                        auto_detect=auto_detect,
                        dry_run=False,
                        queue_enabled=queue_enabled,
                        queue_path=queue_path,
                        fingerprint_history_limit=fingerprint_history_limit,
                        debug=debug,
                    )
                elif telemetry_enabled:
                    last_event_count = send_sample_batches_compact(
                        backend_url,
                        api_key,
                        events_payload,
                        batch_size,
                        auto_detect,
                        queue_enabled=queue_enabled,
                        queue_path=queue_path,
                        state_path=state_path,
                        deduplicate_events=deduplicate_events,
                        fingerprint_history_limit=fingerprint_history_limit,
                        debug=debug,
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
        write_log_file("agent_shutdown reason=KeyboardInterrupt")
        print("\nHexSOC agent shutting down gracefully", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
