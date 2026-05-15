"""IOC normalization utilities for the Threat Intelligence Feed Integrator."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


HASH_LENGTHS = {32, 40, 64}
IOC_TYPES = {"ip", "domain", "url", "hash", "email", "cve"}


@dataclass(frozen=True)
class NormalizedIOC:
    """Validated IOC value ready for deduplication and storage."""

    ioc_type: str
    value: str
    normalized_value: str
    fingerprint: str
    is_valid: bool
    reason: str | None = None


def normalize_ioc_value(value: str, ioc_type: str | None = None) -> NormalizedIOC:
    """Normalize and validate an IOC using stable, provider-neutral rules."""
    raw = (value or "").strip()
    detected_type = (ioc_type or "").strip().lower() or detect_ioc_type(raw)

    if detected_type not in IOC_TYPES:
        return _invalid(detected_type or "unknown", raw, "Unsupported or undetected IOC type")
    if not raw:
        return _invalid(detected_type, raw, "IOC value is empty")

    if detected_type == "ip":
        return _normalize_ip(raw)
    if detected_type == "domain":
        return _normalize_domain(raw)
    if detected_type == "url":
        return _normalize_url(raw)
    if detected_type == "hash":
        return _normalize_hash(raw)
    if detected_type == "email":
        return _normalize_email(raw)
    if detected_type == "cve":
        return _normalize_cve(raw)

    return _invalid(detected_type, raw, "Unsupported IOC type")


def detect_ioc_type(value: str) -> str:
    """Infer IOC type from a raw value when the feed does not provide one."""
    raw = (value or "").strip()
    lowered = raw.lower()

    if not raw:
        return "unknown"
    if re.fullmatch(r"cve-\d{4}-\d{4,}", lowered):
        return "cve"
    if "@" in raw and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", lowered):
        return "email"
    if re.fullmatch(r"[a-fA-F0-9]+", raw) and len(raw) in HASH_LENGTHS:
        return "hash"
    try:
        ipaddress.ip_address(raw)
        return "ip"
    except ValueError:
        pass
    parsed = urlparse(raw)
    if parsed.scheme and (parsed.netloc or "." in parsed.path):
        return "url"
    if _looks_like_domain(raw):
        return "domain"
    return "unknown"


def fingerprint_ioc(ioc_type: str, normalized_value: str) -> str:
    """Create a source-independent fingerprint for IOC deduplication."""
    return sha256(f"{ioc_type.strip().lower()}:{normalized_value.strip().lower()}".encode("utf-8")).hexdigest()


def _normalize_ip(raw: str) -> NormalizedIOC:
    try:
        normalized = str(ipaddress.ip_address(raw))
    except ValueError:
        return _invalid("ip", raw, "Invalid IP address")
    return _valid("ip", raw, normalized)


def _normalize_domain(raw: str) -> NormalizedIOC:
    normalized = raw.lower().strip().rstrip(".")
    if normalized.startswith("*."):
        normalized = normalized[2:]
    if not _looks_like_domain(normalized):
        return _invalid("domain", raw, "Invalid domain")
    return _valid("domain", raw, normalized)


def _normalize_url(raw: str) -> NormalizedIOC:
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return _invalid("url", raw, "URL host is missing")
    port = f":{parsed.port}" if parsed.port else ""
    netloc = f"{host}{port}"
    path = parsed.path or "/"
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    normalized = urlunparse(((parsed.scheme or "http").lower(), netloc, path.rstrip("/") or "/", "", query, ""))
    return _valid("url", raw, normalized)


def _normalize_hash(raw: str) -> NormalizedIOC:
    normalized = raw.lower()
    if not re.fullmatch(r"[a-f0-9]+", normalized) or len(normalized) not in HASH_LENGTHS:
        return _invalid("hash", raw, "Unsupported hash shape")
    return _valid("hash", raw, normalized)


def _normalize_email(raw: str) -> NormalizedIOC:
    normalized = raw.lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", normalized):
        return _invalid("email", raw, "Invalid email address")
    return _valid("email", raw, normalized)


def _normalize_cve(raw: str) -> NormalizedIOC:
    normalized = raw.upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", normalized):
        return _invalid("cve", raw, "Invalid CVE identifier")
    return _valid("cve", raw, normalized)


def _looks_like_domain(value: str) -> bool:
    return bool(
        re.fullmatch(
            r"(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}",
            value,
        )
    )


def _valid(ioc_type: str, value: str, normalized_value: str) -> NormalizedIOC:
    return NormalizedIOC(
        ioc_type=ioc_type,
        value=value.strip(),
        normalized_value=normalized_value,
        fingerprint=fingerprint_ioc(ioc_type, normalized_value),
        is_valid=True,
    )


def _invalid(ioc_type: str, value: str, reason: str) -> NormalizedIOC:
    normalized_value = value.strip().lower()
    return NormalizedIOC(
        ioc_type=ioc_type,
        value=value.strip(),
        normalized_value=normalized_value,
        fingerprint=fingerprint_ioc(ioc_type, normalized_value) if normalized_value else "",
        is_valid=False,
        reason=reason,
    )
