from sqlalchemy import Boolean, JSON, Column, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Shared declarative base for future SQLAlchemy models."""


class TimestampMixin:
    """Common timestamp columns for persistent entities."""

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class SecurityEvent(Base, TimestampMixin):
    """Normalized security telemetry stored for investigation and detection."""

    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(120), nullable=False, index=True)
    event_type = Column(String(120), nullable=False, index=True)
    severity = Column(String(40), nullable=False, default="low", index=True)
    summary = Column(String(500), nullable=True)
    source_ip = Column(String(64), nullable=True, index=True)
    destination_ip = Column(String(64), nullable=True, index=True)
    username = Column(String(120), nullable=True, index=True)
    raw_message = Column(Text, nullable=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)
    raw_payload = Column(JSON, nullable=True)
    risk_score = Column(Integer, nullable=True)
    country = Column(String(120), nullable=True)
    isp = Column(String(255), nullable=True)
    asn = Column(String(120), nullable=True)
    known_malicious = Column(Boolean, nullable=True)
    abuse_confidence_score = Column(Integer, nullable=True)
    total_reports = Column(Integer, nullable=True)
    last_reported_at = Column(DateTime(timezone=True), nullable=True)
    mitre_tactic = Column(String(120), nullable=True)
    mitre_technique = Column(String(160), nullable=True)
    mitre_technique_id = Column(String(40), nullable=True, index=True)
    mitre_confidence = Column(Integer, nullable=True)
    mitre_reason = Column(Text, nullable=True)


class Alert(Base, TimestampMixin):
    """Analyst-facing signal produced from events, rules, or manual triage."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(40), nullable=False, default="medium", index=True)
    status = Column(String(40), nullable=False, default="new", index=True)
    source = Column(String(120), nullable=True)
    description = Column(Text, nullable=True)
    event_id = Column(Integer, ForeignKey("security_events.id"), nullable=True, index=True)
    mitre_tactic = Column(String(120), nullable=True)
    mitre_technique = Column(String(120), nullable=True)
    mitre_technique_id = Column(String(40), nullable=True, index=True)
    confidence_score = Column(Integer, nullable=True)
    detection_rule = Column(String(120), nullable=True, index=True)
    threat_source = Column(String(120), nullable=True)
    threat_score = Column(Integer, nullable=True)
    geo_country = Column(String(120), nullable=True)
    geo_city = Column(String(120), nullable=True)
    isp = Column(String(255), nullable=True)
    enrichment_status = Column(String(40), nullable=True, default="pending")


class Asset(Base, TimestampMixin):
    """Enterprise asset inventory record."""

    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(64), nullable=True, index=True)
    operating_system = Column("os", String(120), nullable=True)
    role = Column(String(120), nullable=True)
    status = Column(String(40), nullable=True)
    asset_type = Column(String(80), nullable=True)
    environment = Column(String(80), nullable=True)
    criticality = Column(String(40), nullable=True, index=True)
    owner = Column(String(120), nullable=True)


class Incident(Base, TimestampMixin):
    """Case-management record for coordinated security response."""

    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(40), nullable=False, default="medium", index=True)
    status = Column(String(40), nullable=False, default="open", index=True)
    summary = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True, index=True)
    assigned_to = Column(String(120), nullable=True, index=True)
    priority = Column(String(40), nullable=True, index=True)
    case_status = Column(String(40), nullable=True, index=True)
    escalation_level = Column(String(40), nullable=True)
    resolution_summary = Column(Text, nullable=True)
    closed_at = Column(DateTime(timezone=True), nullable=True)


class User(Base):
    """SOC platform user for authenticated analyst workflows."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False, unique=True, index=True)
    username = Column(String(120), nullable=False, unique=True, index=True)
    hashed_password = Column(String(500), nullable=False)
    role = Column(String(40), nullable=False, default="analyst", index=True)
    is_active = Column(Boolean, nullable=False, default=True)
    disabled_reason = Column(String(500), nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class LoginAudit(Base):
    """Authentication audit record for SOC user access monitoring."""

    __tablename__ = "login_audits"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    username = Column(String(120), nullable=False, index=True)
    success = Column(Boolean, nullable=False, default=False, index=True)
    reason = Column(String(255), nullable=True)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(500), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Collector(Base):
    """External telemetry collector authenticated by a hashed API key."""

    __tablename__ = "collectors"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(160), nullable=False, index=True)
    description = Column(Text, nullable=True)
    api_key_hash = Column(String(128), nullable=False, index=True)
    key_prefix = Column(String(32), nullable=False, index=True)
    collector_type = Column(String(80), nullable=False, default="custom_json", index=True)
    source_label = Column(String(120), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    agent_version = Column(String(40), nullable=True)
    host_name = Column(String(255), nullable=True)
    os_name = Column(String(120), nullable=True)
    os_version = Column(String(255), nullable=True)
    last_event_count = Column(Integer, nullable=True)
    last_error = Column(Text, nullable=True)
    heartbeat_count = Column(Integer, nullable=False, default=0)
    last_heartbeat_at = Column(DateTime(timezone=True), nullable=True)
    health_status = Column(String(40), nullable=False, default="offline", index=True)
    created_by = Column(String(120), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)


class ThreatIOC(Base, TimestampMixin):
    """Normalized threat intelligence indicator for feed ingestion and correlation."""

    __tablename__ = "threat_iocs"

    id = Column(Integer, primary_key=True, index=True)
    ioc_type = Column(String(40), nullable=False, index=True)
    value = Column(String(1000), nullable=False, index=True)
    normalized_value = Column(String(1000), nullable=False, index=True)
    source = Column(String(120), nullable=False, index=True)
    source_reference = Column(String(500), nullable=True)
    confidence_score = Column(Integer, nullable=False, default=50, index=True)
    risk_score = Column(Integer, nullable=False, default=50, index=True)
    severity = Column(String(40), nullable=False, default="medium", index=True)
    tags = Column(JSON, nullable=True)
    classification = Column(String(120), nullable=True, index=True)
    description = Column(Text, nullable=True)
    first_seen_at = Column(DateTime(timezone=True), nullable=True)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True, index=True)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    raw_payload = Column(JSON, nullable=True)


class ThreatIOCLink(Base):
    """Relationship between a normalized IOC and a SOC entity."""

    __tablename__ = "threat_ioc_links"

    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("threat_iocs.id"), nullable=False, index=True)
    entity_type = Column(String(40), nullable=False, index=True)
    entity_id = Column(Integer, nullable=False, index=True)
    relationship = Column(String(80), nullable=False, default="correlated_with")
    confidence_score = Column(Integer, nullable=False, default=50)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class CaseNote(Base):
    """Analyst note attached to an incident case."""

    __tablename__ = "case_notes"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)
    author = Column(String(120), nullable=False, default="analyst")
    note_type = Column(String(40), nullable=False, default="investigation", index=True)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class CaseEvidence(Base):
    """Evidence record attached to an incident case."""

    __tablename__ = "case_evidence"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)
    evidence_type = Column(String(80), nullable=False, default="analyst_upload_placeholder", index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    source = Column(String(120), nullable=True)
    reference_id = Column(String(120), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ActivityLog(Base):
    """SOC activity timeline entry for audit and operational history."""

    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    action = Column(String(120), nullable=False, index=True)
    entity_type = Column(String(80), nullable=False, index=True)
    entity_id = Column(Integer, nullable=True, index=True)
    message = Column(String(500), nullable=False)
    severity = Column(String(40), nullable=False, default="info", index=True)
    actor_username = Column(String(120), nullable=True)
    actor_role = Column(String(40), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
