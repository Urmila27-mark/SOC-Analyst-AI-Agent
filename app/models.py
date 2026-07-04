"""
Core data model for the SOC agent.

Everything ingested (Windows Event Logs, syslog/auth.log, Suricata EVE JSON,
router logs, etc.) gets normalized into `Event` rows using a common,
ECS-inspired schema. Detections (Sigma rules or anomaly checks) create
`Alert` rows that reference the triggering events. The LLM agent reasons
over Alerts, and any action it takes (or proposes) is logged as an `Action`.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, relationship, sessionmaker


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SourceType(str, enum.Enum):
    WINDOWS_EVENT = "windows_event"
    SYSMON = "sysmon"
    AUTH_LOG = "auth_log"
    SYSLOG = "syslog"
    SURICATA = "suricata"
    ZEEK = "zeek"
    ROUTER = "router"
    HONEYPOT = "honeypot"
    OTHER = "other"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, enum.Enum):
    NEW = "new"
    TRIAGED = "triaged"
    ESCALATED = "escalated"
    ACTION_PROPOSED = "action_proposed"
    ACTION_PENDING_APPROVAL = "action_pending_approval"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class ActionTier(str, enum.Enum):
    AUTO = "auto"              # low blast-radius, executed immediately
    CONFIRM = "confirm"        # high blast-radius, needs human approval


class ActionStatus(str, enum.Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"


class Asset(Base):
    """A host/device on the network, so the agent can weigh criticality."""

    __tablename__ = "assets"

    id = Column(Integer, primary_key=True)
    hostname = Column(String(255), unique=True, nullable=False)
    ip_address = Column(String(64))
    criticality = Column(Integer, default=1)  # 1 (low) - 5 (crown jewel)
    asset_type = Column(String(64))  # laptop, router, nas, server, iot, ...
    notes = Column(Text)
    created_at = Column(DateTime, default=utcnow)

    events = relationship("Event", back_populates="asset")


class Event(Base):
    """
    A single normalized log/telemetry record, regardless of original source.
    This is the common schema every parser in normalizer.py must produce.
    """

    __tablename__ = "events"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    source_type = Column(Enum(SourceType), nullable=False, index=True)

    host = Column(String(255), index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)

    event_type = Column(String(128), index=True)   # e.g. "auth_failure", "process_create", "alert"
    src_ip = Column(String(64), index=True)
    dst_ip = Column(String(64), index=True)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    user = Column(String(255))
    process_name = Column(String(255))
    process_cmdline = Column(Text)
    parent_process = Column(String(255))

    message = Column(Text)          # human-readable summary of the raw line
    raw = Column(JSON)              # full original record, for drill-down

    created_at = Column(DateTime, default=utcnow)

    asset = relationship("Asset", back_populates="events")
    alert_links = relationship("AlertEvent", back_populates="event")


class Alert(Base):
    """A detection produced by a Sigma rule or anomaly check."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=utcnow, index=True)

    rule_name = Column(String(255), nullable=False)
    rule_source = Column(String(64))   # "sigma", "anomaly", "manual"
    severity = Column(Enum(Severity), default=Severity.MEDIUM, index=True)
    status = Column(Enum(AlertStatus), default=AlertStatus.NEW, index=True)

    title = Column(String(500))
    description = Column(Text)

    # Filled in by the agent after triage
    agent_summary = Column(Text)
    agent_confidence = Column(Float)   # 0-1
    agent_reasoning = Column(Text)     # full reasoning trace, for the dashboard
    agent_recommended_actions = Column(JSON)  # list[str], e.g. ["block_ip:1.2.3.4"]

    event_links = relationship("AlertEvent", back_populates="alert")
    actions = relationship("Action", back_populates="alert")


class AlertEvent(Base):
    """Many-to-many link: which events triggered/support a given alert."""

    __tablename__ = "alert_events"

    id = Column(Integer, primary_key=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False)
    event_id = Column(Integer, ForeignKey("events.id"), nullable=False)

    alert = relationship("Alert", back_populates="event_links")
    event = relationship("Event", back_populates="alert_links")


class Action(Base):
    """
    Something the agent proposed or executed in response to an alert.
    tier=AUTO actions execute immediately (low blast-radius, reversible).
    tier=CONFIRM actions sit as PROPOSED until a human approves them.
    """

    __tablename__ = "actions"

    id = Column(Integer, primary_key=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False)
    created_at = Column(DateTime, default=utcnow)

    action_type = Column(String(64), nullable=False)  # "block_ip", "isolate_host", ...
    target = Column(String(255), nullable=False)       # ip, hostname, etc.
    tier = Column(Enum(ActionTier), nullable=False)
    status = Column(Enum(ActionStatus), default=ActionStatus.PROPOSED)

    justification = Column(Text)
    duration_minutes = Column(Integer, nullable=True)  # for timeboxed actions like IP blocks

    executed_at = Column(DateTime, nullable=True)
    reverted_at = Column(DateTime, nullable=True)
    result = Column(Text)

    alert = relationship("Alert", back_populates="actions")


def get_engine(db_path: str = "sqlite:///soc_agent.db"):
    return create_engine(db_path, echo=False, future=True)


def init_db(engine):
    Base.metadata.create_all(engine)


def get_session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)
