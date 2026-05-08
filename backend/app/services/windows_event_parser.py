"""Parsers for Windows Security and Sysmon telemetry."""

from datetime import datetime
from typing import Any

from app.schemas.ingestion import IngestLogItem


SYSMON_EVENT_MAP = {
    1: "process_creation",
    3: "network_connection",
    7: "image_loaded",
    10: "process_access",
    11: "file_created",
    22: "dns_query",
}

WINDOWS_SECURITY_EVENT_MAP = {
    4624: "login_success",
    4625: "failed_login",
    4672: "special_privileges_assigned",
    4688: "process_creation",
    4697: "service_installed",
    4720: "user_created",
    4728: "user_added_to_privileged_group",
    4740: "account_locked_out",
}


def parse_windows_events(raw_events: list[dict[str, Any]]) -> tuple[list[IngestLogItem], list[str]]:
    """Parse raw Windows/Sysmon event dictionaries into normalized ingestion items."""
    parsed: list[IngestLogItem] = []
    errors: list[str] = []

    for index, raw_event in enumerate(raw_events, start=1):
        try:
            parsed.append(parse_windows_event(raw_event))
        except (TypeError, ValueError) as exc:
            errors.append(f"event[{index}] {exc}")

    return parsed, errors


def parse_windows_event(raw_event: dict[str, Any]) -> IngestLogItem:
    """Normalize one Windows or Sysmon event dictionary."""
    if not isinstance(raw_event, dict):
        raise TypeError("must be a JSON object")

    event_id = _event_id(raw_event)
    channel = str(_first(raw_event, "Channel", "channel", "LogName", "ProviderName", "Provider") or "").lower()
    source_name = str(_first(raw_event, "SourceName", "ProviderName", "Provider", "source") or "").lower()
    is_sysmon = "sysmon" in channel or "sysmon" in source_name
    source = "sysmon" if is_sysmon else "windows_security"
    event_type = _mapped_event_type(event_id, is_sysmon)

    fields = _flatten(raw_event)
    command_line = _field(fields, "CommandLine", "ProcessCommandLine", "command_line")
    image = _field(fields, "Image", "NewProcessName", "ProcessName", "process_name")
    message = _message(raw_event, fields)
    query_name = _field(fields, "QueryName", "query", "DomainName")
    combined_text = " ".join(str(value or "") for value in (command_line, image, message, query_name, raw_event)).lower()

    event_type = _detection_oriented_type(event_type, combined_text, command_line, query_name)
    severity = _severity_for(event_type, event_id)

    return IngestLogItem(
        timestamp=_timestamp(raw_event),
        event_type=event_type,
        source=source,
        source_ip=_field(fields, "SourceIp", "IpAddress", "SourceNetworkAddress", "ClientAddress", "src_ip"),
        destination_ip=_field(fields, "DestinationIp", "DestIp", "destination_ip", "dest_ip"),
        username=_username(fields),
        hostname=_field(fields, "Computer", "ComputerName", "Hostname", "HostName", "host", "hostname"),
        severity=severity,
        raw_message=message,
        raw_payload={
            "event_id": event_id,
            "channel": channel or None,
            "provider": source_name or None,
            "image": image,
            "command_line": command_line,
            "query": query_name,
            "raw_event": raw_event,
        },
    )


def _mapped_event_type(event_id: int | None, is_sysmon: bool) -> str:
    if is_sysmon:
        return SYSMON_EVENT_MAP.get(event_id or -1, "sysmon_event")
    return WINDOWS_SECURITY_EVENT_MAP.get(event_id or -1, "windows_event")


def _detection_oriented_type(
    current_type: str,
    combined_text: str,
    command_line: str | None,
    query_name: str | None,
) -> str:
    command = (command_line or "").lower()

    if any(token in combined_text for token in ("trojan", "ransomware", "beacon", "malware")):
        return "malware_indicator"
    if any(token in command for token in ("mimikatz", "sekurlsa", "lsass", "procdump")):
        return "credential_access"
    if any(token in combined_text for token in ("psexec", "wmic", "winrm", "remote service")):
        return "lateral_movement"
    if "powershell" in command and any(token in command for token in ("-enc", "encodedcommand", "iex", "downloadstring")):
        return "suspicious_powershell"
    if current_type == "dns_query" and _looks_suspicious_domain(query_name):
        return "dns_suspicious"
    return current_type


def _severity_for(event_type: str, event_id: int | None) -> str:
    if event_type in {"malware_indicator", "credential_access", "lateral_movement"}:
        return "critical"
    if event_type in {"suspicious_powershell", "failed_login", "special_privileges_assigned", "service_installed"}:
        return "high"
    if event_type in {"dns_suspicious", "account_locked_out", "user_added_to_privileged_group"}:
        return "medium"
    if event_id in {4625, 4672, 4697, 4728, 4740}:
        return "medium"
    return "low"


def _event_id(raw_event: dict[str, Any]) -> int | None:
    value = _first(raw_event, "EventID", "EventId", "event_id", "eventID", "Id", "id")
    if value is None:
        value = _nested(raw_event, ["System", "EventID"]) or _nested(raw_event, ["System", "EventId"])
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _timestamp(raw_event: dict[str, Any]) -> datetime | None:
    value = _first(raw_event, "TimeCreated", "UtcTime", "timestamp", "EventTime", "TimeGenerated")
    value = value or _nested(raw_event, ["System", "TimeCreated", "SystemTime"])
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _message(raw_event: dict[str, Any], fields: dict[str, Any]) -> str | None:
    value = _first(raw_event, "Message", "RenderedDescription", "raw_message", "message")
    value = value or _field(fields, "Message", "RenderedDescription")
    if value:
        return str(value)[:1000]
    event_id = _event_id(raw_event)
    return f"Windows event {event_id}" if event_id else "Windows event"


def _username(fields: dict[str, Any]) -> str | None:
    domain = _field(fields, "TargetDomainName", "SubjectDomainName")
    username = _field(fields, "TargetUserName", "SubjectUserName", "User", "UserName", "AccountName", "username")
    if domain and username and username != "-":
        return f"{domain}\\{username}"
    return username if username and username != "-" else None


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            next_key = f"{prefix}.{key}" if prefix else str(key)
            flattened[next_key] = item
            flattened.update(_flatten(item, next_key))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict) and "Name" in item and "Value" in item:
                flattened[str(item["Name"])] = item["Value"]
            flattened.update(_flatten(item, prefix))
    return flattened


def _field(fields: dict[str, Any], *names: str) -> str | None:
    lowered = {key.lower().split(".")[-1]: value for key, value in fields.items()}
    for name in names:
        value = fields.get(name) or lowered.get(name.lower())
        if value not in (None, ""):
            return str(value)
    return None


def _first(raw_event: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in raw_event:
            return raw_event[name]
    return None


def _nested(raw_event: dict[str, Any], path: list[str]) -> Any:
    current: Any = raw_event
    for part in path:
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _looks_suspicious_domain(domain: str | None) -> bool:
    if not domain:
        return False
    normalized = domain.lower().strip(".")
    labels = normalized.split(".")
    if any(len(label) >= 24 for label in labels):
        return True
    first = labels[0] if labels else ""
    digit_count = sum(character.isdigit() for character in first)
    return len(first) >= 14 and digit_count >= 4
