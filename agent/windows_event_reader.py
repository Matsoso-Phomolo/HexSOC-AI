"""Windows Event Log reader for HexSOC Agent.

This module uses pywin32 when available and fails gracefully elsewhere so the
agent service can keep heartbeating on unsupported hosts.
"""

from __future__ import annotations

import platform
import socket
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any


try:
    import win32evtlog  # type: ignore
except ImportError:  # pragma: no cover - depends on Windows host.
    win32evtlog = None


DEFAULT_CHANNELS = [
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-Sysmon/Operational",
]

EVENT_ID_MAP = {
    "Security": {
        4624: ("login_success", "info"),
        4625: ("failed_login", "medium"),
        4672: ("privileged_logon", "high"),
        4688: ("process_created", "info"),
        4720: ("user_created", "medium"),
        4728: ("user_added_to_privileged_group", "high"),
        4740: ("account_locked", "medium"),
    },
    "Microsoft-Windows-Sysmon/Operational": {
        1: ("process_create", "info"),
        3: ("network_connection", "info"),
        7: ("image_load", "info"),
        8: ("create_remote_thread", "high"),
        10: ("process_access", "medium"),
        11: ("file_create", "info"),
        12: ("registry_event", "medium"),
        13: ("registry_event", "medium"),
        14: ("registry_event", "medium"),
        22: ("dns_query", "info"),
    },
}

SYSTEM_APPLICATION_MAP = {
    7035: ("service_installed", "medium"),
    7036: ("service_installed", "info"),
    7031: ("service_failure", "high"),
    1000: ("application_error", "medium"),
    1001: ("application_error", "medium"),
    41: ("system_error", "high"),
    6008: ("system_error", "high"),
}

LEVEL_SEVERITY = {
    "1": "critical",
    "2": "high",
    "3": "medium",
    "4": "info",
    "5": "info",
}

QUERY_ALL_EVENTS = "*[System[EventRecordID > 0]]"


def is_windows() -> bool:
    """Return whether this host is Windows."""
    return platform.system().lower() == "windows"


def pywin32_available() -> bool:
    """Return whether pywin32 event APIs are importable."""
    return win32evtlog is not None


def unsupported_message() -> str | None:
    """Return a clear reason if Windows Event Log collection is unavailable."""
    if not is_windows():
        return "Windows Event Log collection is only supported on Windows hosts."
    if not pywin32_available():
        return "pywin32 is not installed. Install it with: pip install pywin32"
    return None


def query_flags(direction: str = "forward") -> int:
    """Build pywin32 EvtQuery flags using the channel-path query mode."""
    if win32evtlog is None:
        return 0
    movement = win32evtlog.EvtQueryReverseDirection if direction == "reverse" else win32evtlog.EvtQueryForwardDirection
    return win32evtlog.EvtQueryChannelPath | movement


def evt_query(channel: str, query_text: str, direction: str = "forward") -> Any:
    """Run pywin32 EvtQuery with the officially supported argument order."""
    if win32evtlog is None:
        raise RuntimeError("pywin32 is not installed. Install it with: pip install pywin32")
    return win32evtlog.EvtQuery(channel, query_flags(direction), query_text)


def map_event_type(channel: str, event_id: int | None, provider: str = "") -> tuple[str, str]:
    """Map Windows/Sysmon event IDs to normalized HexSOC event types."""
    if event_id is None:
        return "windows_event", "info"
    if channel in EVENT_ID_MAP and event_id in EVENT_ID_MAP[channel]:
        return EVENT_ID_MAP[channel][event_id]
    if channel in {"System", "Application"} and event_id in SYSTEM_APPLICATION_MAP:
        return SYSTEM_APPLICATION_MAP[event_id]
    if "Service Control Manager" in provider and event_id in {7035, 7036}:
        return "service_installed", "info"
    return "windows_event", "info"


def first_value(fields: dict[str, Any], names: list[str]) -> str | None:
    """Return the first non-empty field value from possible Windows names."""
    for name in names:
        value = fields.get(name)
        if value not in (None, ""):
            return str(value)
    return None


def normalize_event(channel: str, raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize a Windows event dict into HexSOC ingestion format."""
    event_id = raw.get("event_id")
    try:
        event_id_int = int(event_id) if event_id is not None else None
    except (TypeError, ValueError):
        event_id_int = None
    provider = str(raw.get("provider") or "")
    event_type, mapped_severity = map_event_type(channel, event_id_int, provider=provider)
    fields = raw.get("fields") if isinstance(raw.get("fields"), dict) else {}
    timestamp = raw.get("timestamp") or datetime.now(timezone.utc).isoformat()
    hostname = first_value(fields, ["Computer", "Hostname", "HostName"]) or str(raw.get("computer") or socket.gethostname())
    username = first_value(fields, ["TargetUserName", "SubjectUserName", "User", "AccountName"])
    source_ip = first_value(fields, ["IpAddress", "SourceIp", "SourceIpAddress", "SourceAddress"])
    destination_ip = first_value(fields, ["DestinationIp", "DestinationIpAddress", "DestAddress"])
    raw_message = str(raw.get("message") or raw.get("raw_message") or f"{channel} event {event_id_int or 'unknown'}")
    level = str(raw.get("level") or "")
    severity = raw.get("severity") or LEVEL_SEVERITY.get(level, mapped_severity)

    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "source": "windows_event_log",
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "username": username,
        "hostname": hostname,
        "severity": severity,
        "raw_message": raw_message,
        "raw_payload": {
            "channel": channel,
            "event_id": event_id_int,
            "record_id": raw.get("record_id"),
            "provider": provider,
            "computer": raw.get("computer"),
            "fields": fields,
        },
    }


def parse_event_xml(channel: str, xml_payload: str) -> dict[str, Any]:
    """Parse rendered Windows event XML into a raw dict."""
    root = ET.fromstring(xml_payload)
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    system = root.find("e:System", ns)
    event_id = None
    record_id = None
    provider = None
    computer = None
    level = None
    timestamp = None
    if system is not None:
        event_id_node = system.find("e:EventID", ns)
        record_id_node = system.find("e:EventRecordID", ns)
        provider_node = system.find("e:Provider", ns)
        computer_node = system.find("e:Computer", ns)
        level_node = system.find("e:Level", ns)
        time_node = system.find("e:TimeCreated", ns)
        event_id = event_id_node.text if event_id_node is not None else None
        record_id = record_id_node.text if record_id_node is not None else None
        provider = provider_node.attrib.get("Name") if provider_node is not None else None
        computer = computer_node.text if computer_node is not None else None
        level = level_node.text if level_node is not None else None
        timestamp = time_node.attrib.get("SystemTime") if time_node is not None else None
    fields: dict[str, Any] = {}
    for data in root.findall(".//e:EventData/e:Data", ns):
        name = data.attrib.get("Name")
        if name:
            fields[name] = data.text
    return {
        "channel": channel,
        "event_id": event_id,
        "record_id": record_id,
        "provider": provider,
        "computer": computer,
        "level": level,
        "timestamp": timestamp,
        "fields": fields,
        "message": f"{channel} event {event_id or 'unknown'}",
    }


def highest_record_id(channel: str) -> int:
    """Return the current highest record ID for a channel."""
    if win32evtlog is None:
        return 0
    query = evt_query(channel, QUERY_ALL_EVENTS, direction="reverse")
    events = win32evtlog.EvtNext(query, 1)
    if not events:
        return 0
    xml_payload = win32evtlog.EvtRender(events[0], win32evtlog.EvtRenderEventXml)
    raw = parse_event_xml(channel, xml_payload)
    try:
        return int(raw.get("record_id") or 0)
    except (TypeError, ValueError):
        return 0


def read_channel_events(
    channel: str,
    last_record_id: int | None,
    start_position: str,
    max_events: int,
    recent_count: int = 50,
    debug: bool = False,
) -> tuple[list[dict[str, Any]], int, list[str], dict[str, Any]]:
    """Read normalized events from one channel."""
    warnings: list[str] = []
    debug_info: dict[str, Any] = {
        "channel": channel,
        "query": None,
        "flags": None,
        "event_count": 0,
        "first_record_id": None,
        "success": False,
    }
    if win32evtlog is None:
        return [], int(last_record_id or 0), ["pywin32 is not installed. Install it with: pip install pywin32"], debug_info

    current_cursor = int(last_record_id or 0)
    try:
        if current_cursor == 0 and start_position == "latest":
            debug_info["query"] = QUERY_ALL_EVENTS
            debug_info["flags"] = query_flags("reverse")
            cursor = highest_record_id(channel)
            debug_info["success"] = True
            return [], cursor, [], debug_info

        query_text = QUERY_ALL_EVENTS
        if current_cursor:
            query_text = f"*[System[EventRecordID > {current_cursor}]]"
        debug_info["query"] = query_text
        debug_info["flags"] = query_flags("forward")
        query = evt_query(channel, query_text, direction="forward")
        raw_events: list[dict[str, Any]] = []
        while len(raw_events) < max_events:
            handles = win32evtlog.EvtNext(query, min(16, max_events - len(raw_events)))
            if not handles:
                break
            for handle in handles:
                xml_payload = win32evtlog.EvtRender(handle, win32evtlog.EvtRenderEventXml)
                raw_events.append(parse_event_xml(channel, xml_payload))
        if current_cursor == 0 and start_position == "recent":
            raw_events = raw_events[-recent_count:]
        normalized = [normalize_event(channel, item) for item in raw_events]
        debug_info["event_count"] = len(normalized)
        max_record_id = current_cursor
        for event in normalized:
            try:
                record_id = int((event.get("raw_payload") or {}).get("record_id") or 0)
                if debug_info["first_record_id"] is None:
                    debug_info["first_record_id"] = record_id
                max_record_id = max(max_record_id, record_id)
            except (TypeError, ValueError):
                continue
        debug_info["success"] = True
        return normalized, max_record_id, warnings, debug_info
    except Exception as exc:  # noqa: BLE001 - missing channels/permissions should not crash service.
        debug_info["error"] = str(exc)
        return [], current_cursor, [f"{channel}: EvtQuery failed ({exc})"], debug_info


def read_windows_events(
    channels: list[str],
    cursors: dict[str, int],
    batch_size: int = 50,
    max_per_cycle: int = 200,
    start_position: str = "latest",
    recent_count: int = 50,
    debug: bool = False,
) -> dict[str, Any]:
    """Read new Windows events across channels using per-channel cursors."""
    unavailable = unsupported_message()
    if unavailable:
        return {"events": [], "cursors": cursors, "warnings": [unavailable], "available": False, "debug": []}

    events: list[dict[str, Any]] = []
    updated_cursors = dict(cursors)
    warnings: list[str] = []
    debug_records: list[dict[str, Any]] = []
    remaining = max(1, max_per_cycle)
    for channel in channels:
        if remaining <= 0:
            break
        channel_events, cursor, channel_warnings, debug_info = read_channel_events(
            channel=channel,
            last_record_id=updated_cursors.get(channel),
            start_position=start_position,
            max_events=min(batch_size, remaining),
            recent_count=recent_count,
            debug=debug,
        )
        warnings.extend(channel_warnings)
        debug_records.append(debug_info)
        updated_cursors[channel] = cursor
        events.extend(channel_events)
        remaining -= len(channel_events)
    return {"events": events, "cursors": updated_cursors, "warnings": warnings, "available": True, "debug": debug_records}


def validate_channel(channel: str, sample_count: int = 5) -> dict[str, Any]:
    """Validate that a channel can be queried safely."""
    unavailable = unsupported_message()
    if unavailable:
        return {
            "channel": channel,
            "exists": False,
            "success": False,
            "query": QUERY_ALL_EVENTS,
            "flags": None,
            "sample_record_count": 0,
            "first_record_id": None,
            "error": unavailable,
        }
    flags = query_flags("forward")
    try:
        query = evt_query(channel, QUERY_ALL_EVENTS, direction="forward")
        handles = win32evtlog.EvtNext(query, max(1, sample_count)) if win32evtlog is not None else []
        first_record_id = None
        if handles:
            xml_payload = win32evtlog.EvtRender(handles[0], win32evtlog.EvtRenderEventXml)
            raw = parse_event_xml(channel, xml_payload)
            first_record_id = raw.get("record_id")
        return {
            "channel": channel,
            "exists": True,
            "success": True,
            "query": QUERY_ALL_EVENTS,
            "flags": flags,
            "sample_record_count": len(handles or []),
            "first_record_id": first_record_id,
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001 - expose channel permission/missing channel errors.
        return {
            "channel": channel,
            "exists": False,
            "success": False,
            "query": QUERY_ALL_EVENTS,
            "flags": flags,
            "sample_record_count": 0,
            "first_record_id": None,
            "error": str(exc),
        }


def is_sysmon_installed() -> bool:
    """Return whether the Sysmon Windows service appears installed."""
    if not is_windows():
        return False
    for service_name in ("Sysmon64", "Sysmon"):
        try:
            result = subprocess.run(
                ["sc.exe", "query", service_name],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            output = result.stdout.upper()
            if result.returncode == 0 and ("RUNNING" in output or "STOPPED" in output):
                return True
        except Exception:
            continue
    return False


def validate_sysmon(sample_count: int = 5) -> dict[str, Any]:
    """Validate Sysmon service and Operational channel availability."""
    channel_result = validate_channel("Microsoft-Windows-Sysmon/Operational", sample_count=sample_count)
    installed = is_sysmon_installed()
    latest_record_id = None
    if channel_result.get("success"):
        try:
            latest_record_id = highest_record_id("Microsoft-Windows-Sysmon/Operational")
        except Exception:
            latest_record_id = None
    return {
        "sysmon_installed": installed,
        "channel_available": bool(channel_result.get("success")),
        "sample_event_count": channel_result.get("sample_record_count", 0),
        "latest_record_id": latest_record_id,
        "status": "SUCCESS" if installed and channel_result.get("success") else "WARNING",
        "error": channel_result.get("error"),
    }
