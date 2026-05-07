"""Security helpers for future authentication and authorization controls."""


def verify_service_token(token: str | None) -> bool:
    """Minimal placeholder until real identity and access control are added."""
    return bool(token)
