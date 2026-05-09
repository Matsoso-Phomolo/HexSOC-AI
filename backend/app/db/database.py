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
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS mitre_tactic VARCHAR(120)",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS mitre_technique VARCHAR(160)",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS mitre_technique_id VARCHAR(40)",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS mitre_confidence INTEGER",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS mitre_reason TEXT",
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
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_technique_id VARCHAR(40)",
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
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS assigned_to VARCHAR(120)",
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS priority VARCHAR(40)",
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS case_status VARCHAR(40)",
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS escalation_level VARCHAR(40)",
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS resolution_summary TEXT",
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS closed_at TIMESTAMP WITH TIME ZONE",
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
        "ALTER TABLE activity_logs ADD COLUMN IF NOT EXISTS actor_username VARCHAR(120)",
        "ALTER TABLE activity_logs ADD COLUMN IF NOT EXISTS actor_role VARCHAR(40)",
        "ALTER TABLE activity_logs ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL",
        "CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, full_name VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL UNIQUE, username VARCHAR(120) NOT NULL UNIQUE, hashed_password VARCHAR(500) NOT NULL, role VARCHAR(40) NOT NULL DEFAULT 'analyst', is_active BOOLEAN NOT NULL DEFAULT true, created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(255)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(255)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(120)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS hashed_password VARCHAR(500)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(40)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled_reason VARCHAR(500)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP WITH TIME ZONE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL",
        "CREATE SEQUENCE IF NOT EXISTS users_id_seq OWNED BY users.id",
        "ALTER SEQUENCE users_id_seq OWNED BY users.id",
        "ALTER TABLE users ALTER COLUMN id SET DEFAULT nextval('users_id_seq')",
        "UPDATE users SET username = CONCAT('user_', id) WHERE username IS NULL OR username = ''",
        "UPDATE users SET email = CONCAT(username, '@hexsoc.local') WHERE email IS NULL OR email = ''",
        "UPDATE users SET full_name = COALESCE(NULLIF(full_name, ''), username, email, CONCAT('User ', id)) WHERE full_name IS NULL OR full_name = ''",
        "UPDATE users SET created_at = now() WHERE created_at IS NULL",
        "UPDATE users SET role = 'analyst' WHERE role IS NULL",
        "UPDATE users SET is_active = true WHERE is_active IS NULL",
        "ALTER TABLE users ALTER COLUMN role SET DEFAULT 'analyst'",
        "ALTER TABLE users ALTER COLUMN is_active SET DEFAULT true",
        "ALTER TABLE users ALTER COLUMN created_at SET DEFAULT now()",
        """
        DO $$
        DECLARE legacy_column record;
        BEGIN
            FOR legacy_column IN
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'users'
                  AND is_nullable = 'NO'
                  AND column_name NOT IN (
                    'id',
                    'full_name',
                    'email',
                    'username',
                    'hashed_password',
                    'role',
                    'is_active',
                    'created_at'
                  )
            LOOP
                EXECUTE format('ALTER TABLE users ALTER COLUMN %I DROP NOT NULL', legacy_column.column_name);
            END LOOP;
        END $$;
        """,
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email ON users (email)",
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_username ON users (username)",
        """
        SELECT setval(
            'users_id_seq',
            GREATEST(COALESCE((SELECT MAX(id) FROM users), 0), 1),
            (SELECT COUNT(*) > 0 FROM users)
        )
        """,
        "CREATE TABLE IF NOT EXISTS login_audits (id SERIAL PRIMARY KEY, user_id INTEGER, username VARCHAR(120) NOT NULL, success BOOLEAN NOT NULL DEFAULT false, reason VARCHAR(255), ip_address VARCHAR(64), user_agent VARCHAR(500), created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL)",
        "ALTER TABLE login_audits ADD COLUMN IF NOT EXISTS user_id INTEGER",
        "ALTER TABLE login_audits ADD COLUMN IF NOT EXISTS username VARCHAR(120)",
        "ALTER TABLE login_audits ADD COLUMN IF NOT EXISTS success BOOLEAN DEFAULT false",
        "ALTER TABLE login_audits ADD COLUMN IF NOT EXISTS reason VARCHAR(255)",
        "ALTER TABLE login_audits ADD COLUMN IF NOT EXISTS ip_address VARCHAR(64)",
        "ALTER TABLE login_audits ADD COLUMN IF NOT EXISTS user_agent VARCHAR(500)",
        "ALTER TABLE login_audits ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL",
        "CREATE TABLE IF NOT EXISTS collectors (id SERIAL PRIMARY KEY, name VARCHAR(160) NOT NULL, description TEXT, api_key_hash VARCHAR(128) NOT NULL, key_prefix VARCHAR(32) NOT NULL, collector_type VARCHAR(80) NOT NULL DEFAULT 'custom_json', source_label VARCHAR(120), is_active BOOLEAN NOT NULL DEFAULT true, last_seen_at TIMESTAMP WITH TIME ZONE, created_by VARCHAR(120), created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, revoked_at TIMESTAMP WITH TIME ZONE)",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS name VARCHAR(160)",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS description TEXT",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS api_key_hash VARCHAR(128)",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS key_prefix VARCHAR(32)",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS collector_type VARCHAR(80) DEFAULT 'custom_json'",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS source_label VARCHAR(120)",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMP WITH TIME ZONE",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS created_by VARCHAR(120)",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP WITH TIME ZONE",
        "UPDATE collectors SET is_active = true WHERE is_active IS NULL",
        "UPDATE collectors SET collector_type = 'custom_json' WHERE collector_type IS NULL",
        "CREATE INDEX IF NOT EXISTS ix_collectors_key_prefix ON collectors (key_prefix)",
        "CREATE TABLE IF NOT EXISTS case_notes (id SERIAL PRIMARY KEY, incident_id INTEGER NOT NULL, author VARCHAR(120) NOT NULL DEFAULT 'analyst', note_type VARCHAR(40) NOT NULL DEFAULT 'investigation', content TEXT NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL)",
        "CREATE TABLE IF NOT EXISTS case_evidence (id SERIAL PRIMARY KEY, incident_id INTEGER NOT NULL, evidence_type VARCHAR(80) NOT NULL DEFAULT 'analyst_upload_placeholder', title VARCHAR(255) NOT NULL, description TEXT, source VARCHAR(120), reference_id VARCHAR(120), created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL)",
        "ALTER TABLE case_notes ADD COLUMN IF NOT EXISTS incident_id INTEGER",
        "ALTER TABLE case_notes ADD COLUMN IF NOT EXISTS author VARCHAR(120)",
        "ALTER TABLE case_notes ADD COLUMN IF NOT EXISTS note_type VARCHAR(40)",
        "ALTER TABLE case_notes ADD COLUMN IF NOT EXISTS content TEXT",
        "ALTER TABLE case_notes ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL",
        "ALTER TABLE case_evidence ADD COLUMN IF NOT EXISTS incident_id INTEGER",
        "ALTER TABLE case_evidence ADD COLUMN IF NOT EXISTS evidence_type VARCHAR(80)",
        "ALTER TABLE case_evidence ADD COLUMN IF NOT EXISTS title VARCHAR(255)",
        "ALTER TABLE case_evidence ADD COLUMN IF NOT EXISTS description TEXT",
        "ALTER TABLE case_evidence ADD COLUMN IF NOT EXISTS source VARCHAR(120)",
        "ALTER TABLE case_evidence ADD COLUMN IF NOT EXISTS reference_id VARCHAR(120)",
        "ALTER TABLE case_evidence ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL",
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
