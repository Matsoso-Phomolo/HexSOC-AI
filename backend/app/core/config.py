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
    demo_seed_token: str | None = None
    abuseipdb_api_key: str | None = None
    virustotal_api_key: str | None = None
    shodan_api_key: str | None = None


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

    return Settings(
        app_name=os.getenv("APP_NAME", "HexSOC AI"),
        app_env=os.getenv("APP_ENV", "development"),
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
        demo_seed_token=os.getenv("DEMO_SEED_TOKEN"),
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY"),
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY"),
        shodan_api_key=os.getenv("SHODAN_API_KEY"),
    )


settings = load_settings()
