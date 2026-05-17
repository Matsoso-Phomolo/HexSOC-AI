import os

from dotenv import load_dotenv
from pydantic import BaseModel


load_dotenv()


class Settings(BaseModel):
    """Application settings loaded from environment variables."""

    app_name: str = "HexSOC AI"
    app_env: str = "development"
    api_prefix: str = "/api"
    frontend_origin: str = "http://localhost:5173"
    cors_origins: list[str] = ["http://localhost:5173", "https://hexsoc-ai.vercel.app"]
    database_url: str = "postgresql+psycopg2://hexsoc:change-me@localhost:5432/hexsoc"
    kafka_bootstrap_servers: str = "localhost:9092"
    jwt_secret_key: str = "change-me"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 480
    session_idle_timeout_minutes: int = 120
    max_failed_login_attempts: int = 5
    account_lockout_minutes: int = 15
    demo_seed_token: str | None = None
    abuseipdb_api_key: str | None = None
    virustotal_api_key: str | None = None
    otx_api_key: str | None = None
    misp_url: str | None = None
    misp_api_key: str | None = None
    shodan_api_key: str | None = None
    threat_intel_provider_timeout_seconds: int = 8
    threat_intel_provider_cache_ttl_seconds: int = 900
    threat_intel_provider_max_lookups_per_request: int = 25
    startup_schema_sync: str = "auto"
    database_connect_timeout_seconds: int = 10
    notifications_enabled: bool = False
    notification_webhook_url: str | None = None
    notification_email_enabled: bool = False
    notification_email_from: str | None = None
    notification_email_to: str | None = None
    notification_rate_limit_seconds: int = 300


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def load_settings() -> Settings:
    """Build settings without introducing framework-specific configuration logic."""
    frontend_origin = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")
    cors_origins = _split_csv(
        os.getenv("CORS_ORIGINS", f"{frontend_origin},https://hexsoc-ai.vercel.app"),
    )

    if frontend_origin not in cors_origins:
        cors_origins.append(frontend_origin)

    default_app_env = "production" if os.getenv("RENDER") else "development"

    return Settings(
        app_name=os.getenv("APP_NAME", "HexSOC AI"),
        app_env=os.getenv("APP_ENV", default_app_env),
        api_prefix=os.getenv("API_PREFIX", "/api"),
        frontend_origin=frontend_origin,
        cors_origins=cors_origins,
        database_url=os.getenv(
            "DATABASE_URL",
            "postgresql+psycopg2://hexsoc:change-me@localhost:5432/hexsoc",
        ),
        kafka_bootstrap_servers=os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
        jwt_secret_key=os.getenv("JWT_SECRET_KEY", "change-me"),
        jwt_algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
        access_token_expire_minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480")),
        session_idle_timeout_minutes=int(os.getenv("SESSION_IDLE_TIMEOUT_MINUTES", "120")),
        max_failed_login_attempts=int(os.getenv("MAX_FAILED_LOGIN_ATTEMPTS", "5")),
        account_lockout_minutes=int(os.getenv("ACCOUNT_LOCKOUT_MINUTES", "15")),
        demo_seed_token=os.getenv("DEMO_SEED_TOKEN"),
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY"),
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY"),
        otx_api_key=os.getenv("OTX_API_KEY"),
        misp_url=os.getenv("MISP_URL"),
        misp_api_key=os.getenv("MISP_API_KEY"),
        shodan_api_key=os.getenv("SHODAN_API_KEY"),
        threat_intel_provider_timeout_seconds=int(os.getenv("THREAT_INTEL_PROVIDER_TIMEOUT_SECONDS", "8")),
        threat_intel_provider_cache_ttl_seconds=int(os.getenv("THREAT_INTEL_PROVIDER_CACHE_TTL_SECONDS", "900")),
        threat_intel_provider_max_lookups_per_request=int(os.getenv("THREAT_INTEL_PROVIDER_MAX_LOOKUPS_PER_REQUEST", "25")),
        startup_schema_sync=os.getenv("STARTUP_SCHEMA_SYNC", "auto"),
        database_connect_timeout_seconds=int(os.getenv("DATABASE_CONNECT_TIMEOUT_SECONDS", "10")),
        notifications_enabled=os.getenv("NOTIFICATIONS_ENABLED", "false").lower() == "true",
        notification_webhook_url=os.getenv("NOTIFICATION_WEBHOOK_URL") or None,
        notification_email_enabled=os.getenv("NOTIFICATION_EMAIL_ENABLED", "false").lower() == "true",
        notification_email_from=os.getenv("NOTIFICATION_EMAIL_FROM") or None,
        notification_email_to=os.getenv("NOTIFICATION_EMAIL_TO") or None,
        notification_rate_limit_seconds=int(os.getenv("NOTIFICATION_RATE_LIMIT_SECONDS", "300")),
    )


settings = load_settings()
