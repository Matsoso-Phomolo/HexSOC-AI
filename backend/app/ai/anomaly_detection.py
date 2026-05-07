"""Runtime anomaly detection service boundary."""


def score_anomaly(features: dict) -> float:
    """Return a neutral anomaly score until models are connected."""
    _ = features
    return 0.0
