from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String, Text, func
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
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)
    raw_payload = Column(JSON, nullable=True)


class Alert(Base, TimestampMixin):
    """Analyst-facing signal produced from events, rules, or manual triage."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(40), nullable=False, default="medium", index=True)
    status = Column(String(40), nullable=False, default="open", index=True)
    source = Column(String(120), nullable=True)
    description = Column(Text, nullable=True)
    event_id = Column(Integer, ForeignKey("security_events.id"), nullable=True, index=True)


class Asset(Base, TimestampMixin):
    """Enterprise asset inventory record."""

    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(64), nullable=True, index=True)
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
