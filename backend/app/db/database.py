from collections.abc import Generator
import logging

from sqlalchemy import create_engine
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.db.models import Base


logger = logging.getLogger(__name__)


def _database_connect_args() -> dict[str, int]:
    """Return driver-specific connection options for production-safe startup."""
    if settings.database_url.startswith(("postgresql://", "postgresql+psycopg2://")):
        return {"connect_timeout": settings.database_connect_timeout_seconds}
    return {}


engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    future=True,
    connect_args=_database_connect_args(),
)
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
    logger.info("Initializing HexSOC database schema")
    Base.metadata.create_all(bind=engine)
    sync_mode = settings.startup_schema_sync.lower()

    if sync_mode == "off":
        logger.info("Startup schema sync disabled")
        return

    if sync_mode == "full" or (sync_mode == "auto" and settings.app_env.lower() != "production"):
        sync_phase2_schema()
        return

    sync_production_schema()


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
        "CREATE TABLE IF NOT EXISTS collectors (id SERIAL PRIMARY KEY, name VARCHAR(160) NOT NULL, description TEXT, api_key_hash VARCHAR(128) NOT NULL, key_prefix VARCHAR(32) NOT NULL, collector_type VARCHAR(80) NOT NULL DEFAULT 'custom_json', source_label VARCHAR(120), is_active BOOLEAN NOT NULL DEFAULT true, last_seen_at TIMESTAMP WITH TIME ZONE, agent_version VARCHAR(40), host_name VARCHAR(255), os_name VARCHAR(120), os_version VARCHAR(255), last_event_count INTEGER, last_error TEXT, heartbeat_count INTEGER NOT NULL DEFAULT 0, last_heartbeat_at TIMESTAMP WITH TIME ZONE, health_status VARCHAR(40) NOT NULL DEFAULT 'offline', created_by VARCHAR(120), created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, revoked_at TIMESTAMP WITH TIME ZONE)",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS name VARCHAR(160)",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS description TEXT",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS api_key_hash VARCHAR(128)",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS key_prefix VARCHAR(32)",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS collector_type VARCHAR(80) DEFAULT 'custom_json'",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS source_label VARCHAR(120)",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMP WITH TIME ZONE",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS agent_version VARCHAR(40)",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS host_name VARCHAR(255)",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS os_name VARCHAR(120)",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS os_version VARCHAR(255)",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS last_event_count INTEGER",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS last_error TEXT",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS heartbeat_count INTEGER DEFAULT 0",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS last_heartbeat_at TIMESTAMP WITH TIME ZONE",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS health_status VARCHAR(40) DEFAULT 'offline'",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS created_by VARCHAR(120)",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL",
        "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP WITH TIME ZONE",
        "UPDATE collectors SET is_active = true WHERE is_active IS NULL",
        "UPDATE collectors SET collector_type = 'custom_json' WHERE collector_type IS NULL",
        "UPDATE collectors SET heartbeat_count = 0 WHERE heartbeat_count IS NULL",
        "UPDATE collectors SET health_status = CASE WHEN revoked_at IS NOT NULL OR is_active = false THEN 'revoked' ELSE COALESCE(health_status, 'offline') END WHERE health_status IS NULL OR health_status = ''",
        "CREATE INDEX IF NOT EXISTS ix_collectors_key_prefix ON collectors (key_prefix)",
        "CREATE TABLE IF NOT EXISTS threat_iocs (id SERIAL PRIMARY KEY, ioc_type VARCHAR(40) NOT NULL, value VARCHAR(1000) NOT NULL, normalized_value VARCHAR(1000) NOT NULL, fingerprint VARCHAR(64), source VARCHAR(120) NOT NULL, sources JSON, source_count INTEGER NOT NULL DEFAULT 1, source_reference VARCHAR(500), confidence_score INTEGER NOT NULL DEFAULT 50, risk_score INTEGER NOT NULL DEFAULT 50, severity VARCHAR(40) NOT NULL DEFAULT 'medium', tags JSON, classification VARCHAR(120), description TEXT, first_seen_at TIMESTAMP WITH TIME ZONE, last_seen_at TIMESTAMP WITH TIME ZONE, expires_at TIMESTAMP WITH TIME ZONE, is_active BOOLEAN NOT NULL DEFAULT true, raw_payload JSON, raw_context JSON, created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, updated_at TIMESTAMP WITH TIME ZONE)",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS ioc_type VARCHAR(40)",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS value VARCHAR(1000)",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS normalized_value VARCHAR(1000)",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(64)",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS source VARCHAR(120)",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS sources JSON",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS source_count INTEGER DEFAULT 1",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS source_reference VARCHAR(500)",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS confidence_score INTEGER DEFAULT 50",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 50",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS severity VARCHAR(40) DEFAULT 'medium'",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS tags JSON",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS classification VARCHAR(120)",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS description TEXT",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMP WITH TIME ZONE",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMP WITH TIME ZONE",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP WITH TIME ZONE",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS raw_payload JSON",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS raw_context JSON",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE",
        "UPDATE threat_iocs SET fingerprint = encode(sha256((ioc_type || ':' || normalized_value)::bytea), 'hex') WHERE fingerprint IS NULL AND ioc_type IS NOT NULL AND normalized_value IS NOT NULL",
        "UPDATE threat_iocs SET sources = to_json(ARRAY[source]) WHERE sources IS NULL AND source IS NOT NULL",
        "UPDATE threat_iocs SET source_count = COALESCE(json_array_length(sources), 1) WHERE source_count IS NULL",
        "CREATE INDEX IF NOT EXISTS ix_threat_iocs_fingerprint ON threat_iocs (fingerprint)",
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_threat_iocs_source_type_value ON threat_iocs (source, ioc_type, normalized_value)",
        "CREATE INDEX IF NOT EXISTS ix_threat_iocs_type_value ON threat_iocs (ioc_type, normalized_value)",
        "CREATE INDEX IF NOT EXISTS ix_threat_iocs_expires_at ON threat_iocs (expires_at)",
        "CREATE TABLE IF NOT EXISTS threat_ioc_links (id SERIAL PRIMARY KEY, ioc_id INTEGER NOT NULL, entity_type VARCHAR(40) NOT NULL, entity_id INTEGER NOT NULL, relationship VARCHAR(80) NOT NULL DEFAULT 'correlated_with', confidence_score INTEGER NOT NULL DEFAULT 50, created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL)",
        "ALTER TABLE threat_ioc_links ADD COLUMN IF NOT EXISTS ioc_id INTEGER",
        "ALTER TABLE threat_ioc_links ADD COLUMN IF NOT EXISTS entity_type VARCHAR(40)",
        "ALTER TABLE threat_ioc_links ADD COLUMN IF NOT EXISTS entity_id INTEGER",
        "ALTER TABLE threat_ioc_links ADD COLUMN IF NOT EXISTS relationship VARCHAR(80) DEFAULT 'correlated_with'",
        "ALTER TABLE threat_ioc_links ADD COLUMN IF NOT EXISTS confidence_score INTEGER DEFAULT 50",
        "ALTER TABLE threat_ioc_links ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_threat_ioc_links_unique ON threat_ioc_links (ioc_id, entity_type, entity_id, relationship)",
        "CREATE INDEX IF NOT EXISTS ix_threat_ioc_links_entity ON threat_ioc_links (entity_type, entity_id)",
        "CREATE TABLE IF NOT EXISTS attack_chains (id SERIAL PRIMARY KEY, chain_key VARCHAR(255) NOT NULL UNIQUE, stable_fingerprint VARCHAR(64) NOT NULL UNIQUE, title VARCHAR(255) NOT NULL, classification VARCHAR(40) NOT NULL DEFAULT 'suspicious', risk_score INTEGER NOT NULL DEFAULT 0, confidence INTEGER NOT NULL DEFAULT 0, status VARCHAR(40) NOT NULL DEFAULT 'open', source_type VARCHAR(40), source_value VARCHAR(255), stage_count INTEGER NOT NULL DEFAULT 0, event_count INTEGER NOT NULL DEFAULT 0, alert_count INTEGER NOT NULL DEFAULT 0, first_seen TIMESTAMP WITH TIME ZONE, last_seen TIMESTAMP WITH TIME ZONE, mitre_techniques JSON, mitre_tactics JSON, related_assets JSON, related_users JSON, related_iocs JSON, summary TEXT, version INTEGER NOT NULL DEFAULT 1, created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, updated_at TIMESTAMP WITH TIME ZONE)",
        "CREATE TABLE IF NOT EXISTS attack_chain_steps (id SERIAL PRIMARY KEY, attack_chain_id INTEGER NOT NULL, step_index INTEGER NOT NULL, timestamp TIMESTAMP WITH TIME ZONE, stage VARCHAR(120), event_type VARCHAR(120), severity VARCHAR(40), mitre_technique VARCHAR(160), mitre_tactic VARCHAR(120), hostname VARCHAR(255), username VARCHAR(120), source_ip VARCHAR(64), destination_ip VARCHAR(64), event_id INTEGER, alert_id INTEGER, description TEXT, confidence INTEGER, metadata JSON)",
        "CREATE TABLE IF NOT EXISTS campaign_clusters (id SERIAL PRIMARY KEY, campaign_key VARCHAR(255) NOT NULL UNIQUE, stable_fingerprint VARCHAR(64) NOT NULL UNIQUE, title VARCHAR(255) NOT NULL, classification VARCHAR(40) NOT NULL DEFAULT 'suspicious', risk_score INTEGER NOT NULL DEFAULT 0, chain_count INTEGER NOT NULL DEFAULT 0, shared_iocs JSON, shared_source_ips JSON, shared_assets JSON, shared_users JSON, shared_techniques JSON, first_seen TIMESTAMP WITH TIME ZONE, last_seen TIMESTAMP WITH TIME ZONE, summary TEXT, created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, updated_at TIMESTAMP WITH TIME ZONE)",
        "CREATE TABLE IF NOT EXISTS investigation_sessions (id SERIAL PRIMARY KEY, attack_chain_id INTEGER, campaign_cluster_id INTEGER, title VARCHAR(255) NOT NULL, assigned_to VARCHAR(120), status VARCHAR(40) NOT NULL DEFAULT 'open', priority VARCHAR(40), analyst_notes TEXT, evidence_refs JSON, created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, updated_at TIMESTAMP WITH TIME ZONE)",
        "CREATE INDEX IF NOT EXISTS ix_attack_chains_risk_last_seen ON attack_chains (risk_score, last_seen)",
        "CREATE INDEX IF NOT EXISTS ix_attack_chain_steps_chain_order ON attack_chain_steps (attack_chain_id, step_index)",
        "CREATE INDEX IF NOT EXISTS ix_campaign_clusters_risk_last_seen ON campaign_clusters (risk_score, last_seen)",
        "CREATE INDEX IF NOT EXISTS ix_investigation_sessions_chain ON investigation_sessions (attack_chain_id)",
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

    _execute_schema_statements(statements, "full startup schema sync")


def sync_production_schema() -> None:
    """Run only critical additive schema checks during production cold start.

    Render starts should be fast and predictable. The full legacy repair pass is
    still available with STARTUP_SCHEMA_SYNC=full, but production defaults to a
    compact set of current-platform tables and indexes.
    """
    statements = [
        "ALTER TABLE activity_logs ADD COLUMN IF NOT EXISTS actor_username VARCHAR(120)",
        "ALTER TABLE activity_logs ADD COLUMN IF NOT EXISTS actor_role VARCHAR(40)",
        "CREATE TABLE IF NOT EXISTS threat_iocs (id SERIAL PRIMARY KEY, ioc_type VARCHAR(40) NOT NULL, value VARCHAR(1000) NOT NULL, normalized_value VARCHAR(1000) NOT NULL, source VARCHAR(120) NOT NULL, source_reference VARCHAR(500), confidence_score INTEGER NOT NULL DEFAULT 50, risk_score INTEGER NOT NULL DEFAULT 50, severity VARCHAR(40) NOT NULL DEFAULT 'medium', tags JSON, classification VARCHAR(120), description TEXT, first_seen_at TIMESTAMP WITH TIME ZONE, last_seen_at TIMESTAMP WITH TIME ZONE, expires_at TIMESTAMP WITH TIME ZONE, is_active BOOLEAN NOT NULL DEFAULT true, raw_payload JSON, created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, updated_at TIMESTAMP WITH TIME ZONE)",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS ioc_type VARCHAR(40)",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS value VARCHAR(1000)",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS normalized_value VARCHAR(1000)",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(64)",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS source VARCHAR(120)",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS sources JSON",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS source_count INTEGER DEFAULT 1",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS source_reference VARCHAR(500)",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS confidence_score INTEGER DEFAULT 50",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 50",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS severity VARCHAR(40) DEFAULT 'medium'",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS tags JSON",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS classification VARCHAR(120)",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS description TEXT",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMP WITH TIME ZONE",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMP WITH TIME ZONE",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP WITH TIME ZONE",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS raw_payload JSON",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS raw_context JSON",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL",
        "ALTER TABLE threat_iocs ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE",
        "UPDATE threat_iocs SET fingerprint = encode(sha256((ioc_type || ':' || normalized_value)::bytea), 'hex') WHERE fingerprint IS NULL AND ioc_type IS NOT NULL AND normalized_value IS NOT NULL",
        "UPDATE threat_iocs SET sources = to_json(ARRAY[source]) WHERE sources IS NULL AND source IS NOT NULL",
        "UPDATE threat_iocs SET source_count = COALESCE(json_array_length(sources), 1) WHERE source_count IS NULL",
        "CREATE INDEX IF NOT EXISTS ix_threat_iocs_fingerprint ON threat_iocs (fingerprint)",
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_threat_iocs_source_type_value ON threat_iocs (source, ioc_type, normalized_value)",
        "CREATE INDEX IF NOT EXISTS ix_threat_iocs_type_value ON threat_iocs (ioc_type, normalized_value)",
        "CREATE INDEX IF NOT EXISTS ix_threat_iocs_expires_at ON threat_iocs (expires_at)",
        "CREATE TABLE IF NOT EXISTS threat_ioc_links (id SERIAL PRIMARY KEY, ioc_id INTEGER NOT NULL, entity_type VARCHAR(40) NOT NULL, entity_id INTEGER NOT NULL, relationship VARCHAR(80) NOT NULL DEFAULT 'correlated_with', confidence_score INTEGER NOT NULL DEFAULT 50, created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL)",
        "ALTER TABLE threat_ioc_links ADD COLUMN IF NOT EXISTS ioc_id INTEGER",
        "ALTER TABLE threat_ioc_links ADD COLUMN IF NOT EXISTS entity_type VARCHAR(40)",
        "ALTER TABLE threat_ioc_links ADD COLUMN IF NOT EXISTS entity_id INTEGER",
        "ALTER TABLE threat_ioc_links ADD COLUMN IF NOT EXISTS relationship VARCHAR(80) DEFAULT 'correlated_with'",
        "ALTER TABLE threat_ioc_links ADD COLUMN IF NOT EXISTS confidence_score INTEGER DEFAULT 50",
        "ALTER TABLE threat_ioc_links ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_threat_ioc_links_unique ON threat_ioc_links (ioc_id, entity_type, entity_id, relationship)",
        "CREATE INDEX IF NOT EXISTS ix_threat_ioc_links_entity ON threat_ioc_links (entity_type, entity_id)",
        "CREATE TABLE IF NOT EXISTS attack_chains (id SERIAL PRIMARY KEY, chain_key VARCHAR(255) NOT NULL UNIQUE, stable_fingerprint VARCHAR(64) NOT NULL UNIQUE, title VARCHAR(255) NOT NULL, classification VARCHAR(40) NOT NULL DEFAULT 'suspicious', risk_score INTEGER NOT NULL DEFAULT 0, confidence INTEGER NOT NULL DEFAULT 0, status VARCHAR(40) NOT NULL DEFAULT 'open', source_type VARCHAR(40), source_value VARCHAR(255), stage_count INTEGER NOT NULL DEFAULT 0, event_count INTEGER NOT NULL DEFAULT 0, alert_count INTEGER NOT NULL DEFAULT 0, first_seen TIMESTAMP WITH TIME ZONE, last_seen TIMESTAMP WITH TIME ZONE, mitre_techniques JSON, mitre_tactics JSON, related_assets JSON, related_users JSON, related_iocs JSON, summary TEXT, version INTEGER NOT NULL DEFAULT 1, created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, updated_at TIMESTAMP WITH TIME ZONE)",
        "CREATE TABLE IF NOT EXISTS attack_chain_steps (id SERIAL PRIMARY KEY, attack_chain_id INTEGER NOT NULL, step_index INTEGER NOT NULL, timestamp TIMESTAMP WITH TIME ZONE, stage VARCHAR(120), event_type VARCHAR(120), severity VARCHAR(40), mitre_technique VARCHAR(160), mitre_tactic VARCHAR(120), hostname VARCHAR(255), username VARCHAR(120), source_ip VARCHAR(64), destination_ip VARCHAR(64), event_id INTEGER, alert_id INTEGER, description TEXT, confidence INTEGER, metadata JSON)",
        "CREATE TABLE IF NOT EXISTS campaign_clusters (id SERIAL PRIMARY KEY, campaign_key VARCHAR(255) NOT NULL UNIQUE, stable_fingerprint VARCHAR(64) NOT NULL UNIQUE, title VARCHAR(255) NOT NULL, classification VARCHAR(40) NOT NULL DEFAULT 'suspicious', risk_score INTEGER NOT NULL DEFAULT 0, chain_count INTEGER NOT NULL DEFAULT 0, shared_iocs JSON, shared_source_ips JSON, shared_assets JSON, shared_users JSON, shared_techniques JSON, first_seen TIMESTAMP WITH TIME ZONE, last_seen TIMESTAMP WITH TIME ZONE, summary TEXT, created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, updated_at TIMESTAMP WITH TIME ZONE)",
        "CREATE TABLE IF NOT EXISTS investigation_sessions (id SERIAL PRIMARY KEY, attack_chain_id INTEGER, campaign_cluster_id INTEGER, title VARCHAR(255) NOT NULL, assigned_to VARCHAR(120), status VARCHAR(40) NOT NULL DEFAULT 'open', priority VARCHAR(40), analyst_notes TEXT, evidence_refs JSON, created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, updated_at TIMESTAMP WITH TIME ZONE)",
        "CREATE INDEX IF NOT EXISTS ix_attack_chains_risk_last_seen ON attack_chains (risk_score, last_seen)",
        "CREATE INDEX IF NOT EXISTS ix_attack_chain_steps_chain_order ON attack_chain_steps (attack_chain_id, step_index)",
        "CREATE INDEX IF NOT EXISTS ix_campaign_clusters_risk_last_seen ON campaign_clusters (risk_score, last_seen)",
        "CREATE INDEX IF NOT EXISTS ix_investigation_sessions_chain ON investigation_sessions (attack_chain_id)",
    ]
    _execute_schema_statements(statements, "production startup schema sync")


def _execute_schema_statements(statements: list[str], label: str) -> None:
    """Execute additive schema statements without letting one failure block startup."""
    skipped = 0

    for statement in statements:
        try:
            with engine.begin() as connection:
                connection.execute(text(statement))
        except SQLAlchemyError as exc:
            skipped += 1
            logger.warning("Skipped %s statement during %s: %s", statement.splitlines()[0][:120], label, exc)

    if skipped:
        logger.warning("%s completed with %s skipped additive statements", label, skipped)
    else:
        logger.info("%s completed", label)


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
