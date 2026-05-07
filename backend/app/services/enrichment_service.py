"""Telemetry enrichment service for assets, indicators, and context."""


def enrich_event(event: dict) -> dict:
    """Pass events through until enrichment sources are connected."""
    return event
