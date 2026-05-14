"""Adapter registry for threat intelligence feed payload normalization."""

from typing import Any

from app.schemas.threat_ioc import ThreatIOCCreate
from app.services.threat_intel_adapters.generic import normalize_generic_feed
from app.services.threat_intel_adapters.provider_placeholders import (
    normalize_abuseipdb_feed,
    normalize_greynoise_feed,
    normalize_otx_feed,
    normalize_shodan_feed,
    normalize_virustotal_feed,
)


def normalize_feed_payload(source: str, payload: dict[str, Any] | list[dict[str, Any]], default_ttl_days: int = 90) -> list[ThreatIOCCreate]:
    """Normalize a provider payload into IOC create records.

    Provider adapters intentionally avoid external API calls. They convert
    already-received feed payloads into HexSOC's internal IOC contract.
    """
    source_key = source.lower().strip()
    adapters = {
        "abuseipdb": normalize_abuseipdb_feed,
        "alienvault_otx": normalize_otx_feed,
        "otx": normalize_otx_feed,
        "greynoise": normalize_greynoise_feed,
        "shodan": normalize_shodan_feed,
        "virustotal": normalize_virustotal_feed,
        "virus_total": normalize_virustotal_feed,
    }
    adapter = adapters.get(source_key, normalize_generic_feed)
    return adapter(source_key, payload, default_ttl_days)
