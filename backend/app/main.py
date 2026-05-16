from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.api.routes import (
    activity,
    alerts,
    attack_chains,
    assets,
    audit,
    auth,
    cases,
    collectors,
    copilot,
    correlation,
    demo,
    detections,
    events,
    graph,
    health,
    ingestion,
    incidents,
    investigation_recommendations,
    mitre,
    realtime,
    threat_intel,
    threat_intel_feeds,
    users,
    websocket,
    windows_events,
)
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
app.add_middleware(GZipMiddleware, minimum_size=1000)


@app.get("/", tags=["root"])
def read_root() -> dict[str, str]:
    """Return API identity for operators and platform checks."""
    return {"service": settings.app_name, "status": "running"}


@app.on_event("startup")
def on_startup() -> None:
    """Initialize starter database tables for Phase 2 development."""
    init_db()


app.include_router(health.router, prefix=settings.api_prefix)
app.include_router(demo.router, prefix=f"{settings.api_prefix}/demo", tags=["demo"])
app.include_router(activity.router, prefix=f"{settings.api_prefix}/activity", tags=["activity"])
app.include_router(audit.router, prefix=f"{settings.api_prefix}/audit", tags=["audit"])
app.include_router(attack_chains.router, prefix=settings.api_prefix, tags=["attack-chains"])
app.include_router(investigation_recommendations.router, prefix=f"{settings.api_prefix}/investigation", tags=["investigation"])
app.include_router(auth.router, prefix=f"{settings.api_prefix}/auth", tags=["auth"])
app.include_router(users.router, prefix=f"{settings.api_prefix}/users", tags=["users"])
app.include_router(assets.router, prefix=f"{settings.api_prefix}/assets", tags=["assets"])
app.include_router(events.router, prefix=f"{settings.api_prefix}/events", tags=["events"])
app.include_router(alerts.router, prefix=f"{settings.api_prefix}/alerts", tags=["alerts"])
app.include_router(incidents.router, prefix=f"{settings.api_prefix}/incidents", tags=["incidents"])
app.include_router(cases.router, prefix=f"{settings.api_prefix}/cases", tags=["cases"])
app.include_router(collectors.router, prefix=f"{settings.api_prefix}/collectors", tags=["collectors"])
app.include_router(detections.router, prefix=f"{settings.api_prefix}/detections", tags=["detections"])
app.include_router(copilot.router, prefix=f"{settings.api_prefix}/copilot", tags=["copilot"])
app.include_router(correlation.router, prefix=f"{settings.api_prefix}/correlation", tags=["correlation"])
app.include_router(threat_intel.router, prefix=f"{settings.api_prefix}/threat-intel", tags=["threat-intel"])
app.include_router(threat_intel_feeds.router, prefix=f"{settings.api_prefix}/threat-intel", tags=["threat-intel-feeds"])
app.include_router(graph.router, prefix=f"{settings.api_prefix}/graph", tags=["graph"])
app.include_router(mitre.router, prefix=f"{settings.api_prefix}/mitre", tags=["mitre"])
app.include_router(ingestion.router, prefix=f"{settings.api_prefix}/ingestion", tags=["ingestion"])
app.include_router(windows_events.router, prefix=f"{settings.api_prefix}/ingestion", tags=["ingestion"])
app.include_router(websocket.router, prefix=f"{settings.api_prefix}/ws", tags=["websocket"])
app.include_router(realtime.router, tags=["realtime"])
