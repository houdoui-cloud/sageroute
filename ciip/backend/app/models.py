import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


def aware(dt: datetime | None) -> datetime | None:
    """SQLite drops tzinfo; every stored timestamp is UTC."""
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentStatus(StrEnum):
    NEW = "new"
    TRIAGED = "triaged"
    IN_PROGRESS = "in_progress"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"
    REJECTED = "rejected"


class Category(StrEnum):
    PHISHING = "phishing"
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    DDOS = "ddos"
    DATA_BREACH = "data_breach"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    ACCOUNT_COMPROMISE = "account_compromise"
    MOBILE_MONEY_FRAUD = "mobile_money_fraud"
    DEFACEMENT = "defacement"
    SOCIAL_ENGINEERING = "social_engineering"
    OTHER = "other"


class Channel(StrEnum):
    WEB = "web"
    PUBLIC_FORM = "public_form"
    EMAIL = "email"
    SMS = "sms"
    WHATSAPP = "whatsapp"
    PHONE = "phone"
    API = "api"


class EscalationLevel(StrEnum):
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"
    EXTERNAL = "external"  # national CERT / regulator — requires approval


class IocType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    PHONE = "phone"  # fraud numbers (mobile money scams)


class Tlp(StrEnum):
    CLEAR = "clear"
    GREEN = "green"
    AMBER = "amber"
    AMBER_STRICT = "amber+strict"
    RED = "red"


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    sector: Mapped[str] = mapped_column(String(80), default="autre")
    country: Mapped[str] = mapped_column(String(80), default="")
    # Hash of the token webhooks (email/SMS/WhatsApp gateways) must present.
    intake_token_hash: Mapped[str | None] = mapped_column(String(128))
    retention_days: Mapped[int] = mapped_column(Integer, default=365)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    incident_seq: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(200))
    password_hash: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(32))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    organization: Mapped[Organization] = relationship(lazy="joined")


incident_iocs = Table(
    "incident_iocs",
    Base.metadata,
    Column("incident_id", ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("ioc_id", ForeignKey("iocs.id", ondelete="CASCADE"), primary_key=True),
)


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (UniqueConstraint("organization_id", "reference"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    reference: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(40), default=Category.OTHER)
    severity: Mapped[str] = mapped_column(String(16), default=Severity.MEDIUM, index=True)
    status: Mapped[str] = mapped_column(String(16), default=IncidentStatus.NEW, index=True)
    source_channel: Mapped[str] = mapped_column(String(20), default=Channel.WEB)
    escalation_level: Mapped[str] = mapped_column(String(16), default=EscalationLevel.L1)
    affected_assets: Mapped[list] = mapped_column(JSON, default=list)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    playbook_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("playbooks.id"))
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    sla_ack_due: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sla_resolve_due: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    assignee: Mapped[User | None] = relationship(foreign_keys=[assignee_id], lazy="joined")
    iocs: Mapped[list["Ioc"]] = relationship(secondary=incident_iocs, back_populates="incidents")
    events: Mapped[list["IncidentEvent"]] = relationship(
        order_by="IncidentEvent.created_at", cascade="all, delete-orphan"
    )


class IncidentEvent(Base):
    """Timeline entry: comment, status change, assignment, escalation…"""

    __tablename__ = "incident_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    kind: Mapped[str] = mapped_column(String(32))
    message: Mapped[str] = mapped_column(Text, default="")
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    actor: Mapped[User | None] = relationship(lazy="joined")


class Escalation(Base):
    __tablename__ = "escalations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    from_level: Mapped[str] = mapped_column(String(16))
    to_level: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(Text)
    escalated_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IntakeReport(Base):
    """A raw signalement from any channel, before triage."""

    __tablename__ = "intake_reports"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    tracking_code: Mapped[str] = mapped_column(String(20), unique=True, index=True)
    channel: Mapped[str] = mapped_column(String(20))
    subject: Mapped[str] = mapped_column(String(300))
    body: Mapped[str] = mapped_column(Text)
    category_hint: Mapped[str | None] = mapped_column(String(40))
    # Reporter PII is encrypted at rest (Fernet).
    reporter_name_enc: Mapped[str | None] = mapped_column(Text)
    reporter_email_enc: Mapped[str | None] = mapped_column(Text)
    reporter_phone_enc: Mapped[str | None] = mapped_column(Text)
    is_anonymous: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(16), default="received", index=True)
    rejection_reason: Mapped[str | None] = mapped_column(Text)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("incidents.id"))
    submitted_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    triaged_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class Ioc(Base):
    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("organization_id", "type", "value"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    type: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(2048), index=True)
    tlp: Mapped[str] = mapped_column(String(16), default=Tlp.AMBER)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    source: Mapped[str] = mapped_column(String(200), default="interne")
    description: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    shared: Mapped[bool] = mapped_column(Boolean, default=False)
    sightings: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))

    incidents: Mapped[list[Incident]] = relationship(secondary=incident_iocs, back_populates="iocs")


class IntelItem(Base):
    """OSINT / threat-intel bulletin (fictional feeds in the demo)."""

    __tablename__ = "intel_items"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    source: Mapped[str] = mapped_column(String(200))
    external_id: Mapped[str] = mapped_column(String(100))
    title: Mapped[str] = mapped_column(String(300))
    summary: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), default=Severity.MEDIUM)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    region: Mapped[str] = mapped_column(String(80), default="Afrique")
    indicators: Mapped[list] = mapped_column(JSON, default=list)
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (UniqueConstraint("organization_id", "source", "external_id"),)


class Playbook(Base):
    __tablename__ = "playbooks"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    # NULL = platform-wide reference playbook, readable by every organisation.
    organization_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(40))
    description: Mapped[str] = mapped_column(Text, default="")
    steps: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16), default="active")  # draft | active | archived
    generated_by_ai: Mapped[bool] = mapped_column(Boolean, default=False)
    validated_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AiSuggestion(Base):
    """Output of the assistant. Never applied without human validation."""

    __tablename__ = "ai_suggestions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(20))  # triage | playbook | answer
    engine: Mapped[str] = mapped_column(String(60))  # "ollama:<model>" | "rules"
    prompt_redacted: Mapped[str] = mapped_column(Text, default="")
    output: Mapped[dict] = mapped_column(JSON, default=dict)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(16), default="proposed")  # proposed|validated|rejected
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    reviewed_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    review_comment: Mapped[str | None] = mapped_column(Text)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DecisionRequest(Base):
    """Four-eyes approval for sensitive actions."""

    __tablename__ = "decision_requests"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    type: Mapped[str] = mapped_column(String(40))
    target_type: Mapped[str] = mapped_column(String(40))
    target_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    justification: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    requested_by_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    reviewed_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    review_comment: Mapped[str | None] = mapped_column(Text)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    requested_by: Mapped[User] = relationship(foreign_keys=[requested_by_id], lazy="joined")
    reviewed_by: Mapped[User | None] = relationship(foreign_keys=[reviewed_by_id], lazy="joined")


class AuditLog(Base):
    """Append-only, hash-chained journal of every significant action."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, index=True)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    actor_email: Mapped[str | None] = mapped_column(String(254))
    action: Mapped[str] = mapped_column(String(80), index=True)
    target_type: Mapped[str | None] = mapped_column(String(40))
    target_id: Mapped[str | None] = mapped_column(String(64))
    ip: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), unique=True)
