import os

from dotenv import load_dotenv
from pydantic import BaseModel


load_dotenv()


class Settings(BaseModel):
    """Application settings loaded from environment variables."""

    app_name: str = "HexSOC AI"
    app_env: str = "development"
    api_prefix: str = "/api"
    cors_origins: list[str] = ["http://localhost:5173"]
    database_url: str = "postgresql+psycopg2://hexsoc:change-me@localhost:5432/hexsoc"
    kafka_bootstrap_servers: str = "localhost:9092"
    jwt_secret_key: str = "change-me"
    jwt_algorithm: str = "HS256"


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def load_settings() -> Settings:
    """Build settings without introducing framework-specific configuration logic."""
    return Settings(
        app_name=os.getenv("APP_NAME", "HexSOC AI"),
        app_env=os.getenv("APP_ENV", "development"),
        api_prefix=os.getenv("API_PREFIX", "/api"),
        cors_origins=_split_csv(os.getenv("CORS_ORIGINS", "http://localhost:5173")),
        database_url=os.getenv(
            "DATABASE_URL",
            "postgresql+psycopg2://hexsoc:change-me@localhost:5432/hexsoc",
        ),
        kafka_bootstrap_servers=os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
        jwt_secret_key=os.getenv("JWT_SECRET_KEY", "change-me"),
        jwt_algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
    )


settings = load_settings()
