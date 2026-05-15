"""Bounded IOC extraction from telemetry, alerts, and raw payloads."""

from __future__ import annotations

import json
import re
from typing import Any

from app.services.ioc_normalizer import normalize_ioc_value


SAFE_FIELDS = {
    "message",
    "description",
    "summary",
    "raw_message",
    "source_ip",
    "destination_ip",
    "command_line",
    "process_name",
    "file_hash",
    "url",
    "domain",
    "username",
    "raw_payload",
}

PATTERNS = [
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
    re.compile(r"\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b"),
    re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE),
    re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b"),
]


def extract_iocs(payload: dict[str, Any], limit: int = 100) -> list[dict[str, Any]]:
    """Extract and normalize IOC candidates from bounded safe fields."""
    text_values = _safe_text_values(payload)
    candidates: dict[str, dict[str, Any]] = {}

    for text in text_values:
        for pattern in PATTERNS:
            for match in pattern.findall(text):
                normalized = normalize_ioc_value(match)
                if not normalized.is_valid:
                    continue
                if normalized.ioc_type == "domain" and _likely_false_positive_domain(normalized.normalized_value):
                    continue
                candidates[normalized.fingerprint] = {
                    "ioc_type": normalized.ioc_type,
                    "value": normalized.value,
                    "normalized_value": normalized.normalized_value,
                    "fingerprint": normalized.fingerprint,
                }
                if len(candidates) >= limit:
                    return list(candidates.values())

    return list(candidates.values())


def _safe_text_values(payload: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for field in SAFE_FIELDS:
        value = payload.get(field)
        if value is None:
            continue
        if isinstance(value, dict):
            values.append(json.dumps(_trim_dict(value), default=str)[:5000])
        elif isinstance(value, list):
            values.append(json.dumps(value[:50], default=str)[:5000])
        else:
            values.append(str(value)[:5000])
    return values


def _trim_dict(value: dict[str, Any]) -> dict[str, Any]:
    return {key: value[key] for key in list(value.keys())[:50]}


def _likely_false_positive_domain(value: str) -> bool:
    return value.endswith((".local", ".internal", ".lan")) or value in {"windows.local"}
