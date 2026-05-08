from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.db.models import Base


engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db_session() -> Generator:
    """Yield a database session for API dependencies."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create starter tables until formal migrations are introduced."""
    Base.metadata.create_all(bind=engine)
    sync_phase2_schema()


def sync_phase2_schema() -> None:
    """Apply safe additive schema updates for the Phase 2 foundation.

    This keeps local development databases usable until Alembic migrations are
    introduced. Statements are additive only and do not drop or rewrite data.
    """
    statements = [
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS ip_address VARCHAR(64)",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS os VARCHAR(120)",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS role VARCHAR(120)",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS status VARCHAR(40)",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS asset_type VARCHAR(80)",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS environment VARCHAR(80)",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS criticality VARCHAR(40)",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS owner VARCHAR(120)",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE",
        _drop_not_null_if_exists("assets", "os"),
        _drop_not_null_if_exists("assets", "role"),
        _drop_not_null_if_exists("assets", "status"),
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS source VARCHAR(120)",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS event_type VARCHAR(120)",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS severity VARCHAR(40)",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS summary VARCHAR(500)",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS source_ip VARCHAR(64)",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS destination_ip VARCHAR(64)",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS username VARCHAR(120)",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS raw_message TEXT",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS asset_id INTEGER",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS raw_payload JSON",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS risk_score INTEGER",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS country VARCHAR(120)",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS isp VARCHAR(255)",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS asn VARCHAR(120)",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS known_malicious BOOLEAN",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS abuse_confidence_score INTEGER",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS total_reports INTEGER",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS last_reported_at TIMESTAMP WITH TIME ZONE",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS title VARCHAR(255)",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS severity VARCHAR(40)",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS status VARCHAR(40)",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS source VARCHAR(120)",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS description TEXT",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS event_id INTEGER",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_tactic VARCHAR(120)",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_technique VARCHAR(120)",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS confidence_score INTEGER",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS detection_rule VARCHAR(120)",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS threat_source VARCHAR(120)",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS threat_score INTEGER",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS geo_country VARCHAR(120)",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS geo_city VARCHAR(120)",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS isp VARCHAR(255)",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS enrichment_status VARCHAR(40)",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE",
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL",
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS title VARCHAR(255)",
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS severity VARCHAR(40)",
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS status VARCHAR(40)",
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS summary TEXT",
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS description TEXT",
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS alert_id INTEGER",
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE",
        _drop_not_null_if_exists("incidents", "attack_type"),
        _drop_not_null_if_exists("incidents", "source_ip"),
        _drop_not_null_if_exists("incidents", "target_id"),
        _drop_not_null_if_exists("incidents", "confidence"),
        _drop_not_null_if_exists("incidents", "blocked"),
        _drop_not_null_if_exists("incidents", "time"),
        "ALTER TABLE activity_logs ADD COLUMN IF NOT EXISTS action VARCHAR(120)",
        "ALTER TABLE activity_logs ADD COLUMN IF NOT EXISTS entity_type VARCHAR(80)",
        "ALTER TABLE activity_logs ADD COLUMN IF NOT EXISTS entity_id INTEGER",
        "ALTER TABLE activity_logs ADD COLUMN IF NOT EXISTS message VARCHAR(500)",
        "ALTER TABLE activity_logs ADD COLUMN IF NOT EXISTS severity VARCHAR(40)",
        "ALTER TABLE activity_logs ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL",
    ]

    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _drop_not_null_if_exists(table_name: str, column_name: str) -> str:
    """Build a PostgreSQL-safe statement for relaxing legacy columns."""
    return f"""
    DO $$
    BEGIN
        IF EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = '{table_name}'
              AND column_name = '{column_name}'
        ) THEN
            ALTER TABLE {table_name} ALTER COLUMN {column_name} DROP NOT NULL;
        END IF;
    END $$;
    """
