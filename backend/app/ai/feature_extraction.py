"""Feature extraction utilities for security telemetry."""


def extract_features(event: dict) -> dict:
    """Extract starter features from a normalized event."""
    return {"source": event.get("source"), "event_type": event.get("event_type")}
