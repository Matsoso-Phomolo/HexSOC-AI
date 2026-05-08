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
