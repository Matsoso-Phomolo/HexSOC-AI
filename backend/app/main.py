from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import activity, alerts, assets, detections, events, health, incidents, websocket
from app.core.config import settings
from app.core.logging import configure_logging
from app.db.database import init_db


configure_logging()

app = FastAPI(
    title=settings.app_name,
    description="Enterprise SOC, AI detection, and security operations API.",
    version="0.1.0",
)

# CORS is open to configured frontend origins for local development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["root"])
def read_root() -> dict[str, str]:
    """Return API identity for operators and platform checks."""
    return {"service": settings.app_name, "status": "running"}


@app.on_event("startup")
def on_startup() -> None:
    """Initialize starter database tables for Phase 2 development."""
    init_db()


app.include_router(health.router, prefix=settings.api_prefix)
app.include_router(activity.router, prefix=f"{settings.api_prefix}/activity", tags=["activity"])
app.include_router(assets.router, prefix=f"{settings.api_prefix}/assets", tags=["assets"])
app.include_router(events.router, prefix=f"{settings.api_prefix}/events", tags=["events"])
app.include_router(alerts.router, prefix=f"{settings.api_prefix}/alerts", tags=["alerts"])
app.include_router(incidents.router, prefix=f"{settings.api_prefix}/incidents", tags=["incidents"])
app.include_router(detections.router, prefix=f"{settings.api_prefix}/detections", tags=["detections"])
app.include_router(websocket.router, prefix=f"{settings.api_prefix}/ws", tags=["websocket"])
