from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health", summary="Service health check")
def health_check() -> dict[str, str]:
    """Return basic service health for load balancers and uptime checks."""
    return {"status": "ok", "service": "hexsoc-ai-api"}
