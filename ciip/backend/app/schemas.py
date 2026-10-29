import uuid
from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.core.rbac import Role
from app.core.security import validate_password_strength
from app.models import Category, Channel, EscalationLevel, IncidentStatus, IocType, Severity, Tlp

T = TypeVar("T")


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- Auth -----------------------------------------------------------------

class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=200)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshIn(BaseModel):
    refresh_token: str


class OrgOut(ORM):
    id: uuid.UUID
    name: str
    slug: str
    sector: str
    country: str
    retention_days: int
    is_active: bool


class MeOut(ORM):
    id: uuid.UUID
    email: str
    full_name: str
    role: str
    organization: OrgOut
    permissions: list[str]


class PasswordChangeIn(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def _strong(cls, v: str) -> str:
        validate_password_strength(v)
        return v


# --- Users / admin --------------------------------------------------------

class UserOut(ORM):
    id: uuid.UUID
    email: str
    full_name: str
    role: str
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime


class UserBrief(ORM):
    id: uuid.UUID
    full_name: str
    role: str


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=200)
    role: Role
    password: str

    @field_validator("password")
    @classmethod
    def _strong(cls, v: str) -> str:
        validate_password_strength(v)
        return v


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, min_length=2, max_length=200)
    role: Role | None = None
    is_active: bool | None = None


class OrgCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    slug: str = Field(pattern=r"^[a-z0-9-]{2,80}$")
    sector: str = "autre"
    country: str = ""
    admin_email: EmailStr
    admin_name: str
    admin_password: str

    @field_validator("admin_password")
    @classmethod
    def _strong(cls, v: str) -> str:
        validate_password_strength(v)
        return v


class OrgSettingsIn(BaseModel):
    retention_days: int | None = Field(default=None, ge=30, le=3650)


class AuditOut(ORM):
    id: int
    organization_id: uuid.UUID | None
    actor_email: str | None
    action: str
    target_type: str | None
    target_id: str | None
    ip: str | None
    details: dict
    created_at: datetime
    hash: str


# --- Incidents ------------------------------------------------------------

class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    description: str = Field(default="", max_length=20000)
    category: Category = Category.OTHER
    severity: Severity = Severity.MEDIUM
    source_channel: Channel = Channel.WEB
    affected_assets: list[str] = Field(default_factory=list, max_length=100)
    tags: list[str] = Field(default_factory=list, max_length=30)
    assignee_id: uuid.UUID | None = None


class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=300)
    description: str | None = Field(default=None, max_length=20000)
    category: Category | None = None
    severity: Severity | None = None
    affected_assets: list[str] | None = None
    tags: list[str] | None = None
    playbook_id: uuid.UUID | None = None


class StatusChange(BaseModel):
    status: IncidentStatus
    comment: str = Field(default="", max_length=5000)


class AssignIn(BaseModel):
    assignee_id: uuid.UUID | None


class CommentIn(BaseModel):
    message: str = Field(min_length=1, max_length=10000)


class EscalateIn(BaseModel):
    to_level: EscalationLevel
    reason: str = Field(min_length=5, max_length=5000)


class EventOut(ORM):
    id: uuid.UUID
    kind: str
    message: str
    data: dict
    created_at: datetime
    actor: UserBrief | None


class IocBrief(ORM):
    id: uuid.UUID
    type: str
    value: str
    tlp: str
    confidence: int


class IncidentOut(ORM):
    id: uuid.UUID
    reference: str
    title: str
    description: str
    category: str
    severity: str
    status: str
    source_channel: str
    escalation_level: str
    affected_assets: list[str]
    tags: list[str]
    playbook_id: uuid.UUID | None
    assignee: UserBrief | None
    sla_ack_due: datetime | None
    sla_resolve_due: datetime | None
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    closed_at: datetime | None
    created_at: datetime
    updated_at: datetime
    sla_breached: bool = False


class IncidentDetail(IncidentOut):
    events: list[EventOut]
    iocs: list[IocBrief]
    pending_decisions: int = 0


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    size: int


# --- Intake ---------------------------------------------------------------

class ReporterIn(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    email: EmailStr | None = None
    phone: str | None = Field(default=None, max_length=40)


class IntakeIn(BaseModel):
    channel: Channel = Channel.WEB
    subject: str = Field(min_length=3, max_length=300)
    body: str = Field(min_length=10, max_length=20000)
    category_hint: Category | None = None
    reporter: ReporterIn | None = None
    is_anonymous: bool = False


class PublicIntakeIn(BaseModel):
    subject: str = Field(min_length=3, max_length=300)
    body: str = Field(min_length=10, max_length=20000)
    category_hint: Category | None = None
    reporter: ReporterIn | None = None
    # Honeypot field: humans never fill it, naive bots do.
    website: str | None = None


class WebhookIntakeIn(BaseModel):
    sender: str = Field(max_length=254)
    subject: str | None = Field(default=None, max_length=300)
    body: str = Field(min_length=1, max_length=20000)


class IntakeOut(ORM):
    id: uuid.UUID
    tracking_code: str
    channel: str
    subject: str
    body: str
    category_hint: str | None
    is_anonymous: bool
    status: str
    rejection_reason: str | None
    incident_id: uuid.UUID | None
    created_at: datetime
    reporter_name: str | None = None
    reporter_email: str | None = None
    reporter_phone: str | None = None
    pii_masked: bool = True


class IntakeReceipt(BaseModel):
    tracking_code: str
    status: str
    message: str


class ConvertIn(BaseModel):
    severity: Severity = Severity.MEDIUM
    category: Category | None = None
    title: str | None = Field(default=None, max_length=300)
    merge_into_incident_id: uuid.UUID | None = None


class RejectIn(BaseModel):
    reason: str = Field(min_length=3, max_length=2000)


# --- Intel ----------------------------------------------------------------

class IocCreate(BaseModel):
    value: str = Field(min_length=3, max_length=2048)
    type: IocType | None = None  # auto-detected when omitted
    tlp: Tlp = Tlp.AMBER
    confidence: int = Field(default=50, ge=0, le=100)
    source: str = Field(default="interne", max_length=200)
    description: str = Field(default="", max_length=5000)
    tags: list[str] = Field(default_factory=list, max_length=30)
    incident_id: uuid.UUID | None = None


class IocUpdate(BaseModel):
    tlp: Tlp | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    description: str | None = None
    tags: list[str] | None = None
    is_active: bool | None = None


class IocOut(ORM):
    id: uuid.UUID
    type: str
    value: str
    tlp: str
    confidence: int
    source: str
    description: str
    tags: list[str]
    is_active: bool
    shared: bool
    sightings: int
    first_seen: datetime
    last_seen: datetime
    is_community: bool = False
    incident_refs: list[str] = []


class IocImportIn(BaseModel):
    text: str = Field(min_length=1, max_length=200000)
    tlp: Tlp = Tlp.AMBER
    source: str = "import"
    confidence: int = Field(default=50, ge=0, le=100)


class MatchIn(BaseModel):
    text: str = Field(min_length=1, max_length=200000)


class IntelItemOut(ORM):
    id: uuid.UUID
    source: str
    title: str
    summary: str
    severity: str
    tags: list[str]
    region: str
    indicators: list
    published_at: datetime


# --- AI -------------------------------------------------------------------

class TriageIn(BaseModel):
    incident_id: uuid.UUID | None = None
    text: str | None = Field(default=None, max_length=20000)


class PlaybookGenIn(BaseModel):
    category: Category
    context: str = Field(default="", max_length=5000)
    incident_id: uuid.UUID | None = None


class AskIn(BaseModel):
    question: str = Field(min_length=3, max_length=4000)
    incident_id: uuid.UUID | None = None


class SuggestionOut(ORM):
    id: uuid.UUID
    incident_id: uuid.UUID | None
    kind: str
    engine: str
    prompt_redacted: str
    output: dict
    confidence: float
    status: str
    review_comment: str | None
    reviewed_at: datetime | None
    created_at: datetime


class ReviewIn(BaseModel):
    approve: bool
    comment: str = Field(default="", max_length=2000)


class PlaybookOut(ORM):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    name: str
    category: str
    description: str
    steps: list
    status: str
    generated_by_ai: bool
    created_at: datetime


class PlaybookIn(BaseModel):
    name: str = Field(min_length=3, max_length=200)
    category: Category
    description: str = ""
    steps: list[dict] = Field(min_length=1, max_length=50)


# --- Decisions ------------------------------------------------------------

class DecisionIn(BaseModel):
    type: str
    target_id: uuid.UUID | None = None
    justification: str = Field(min_length=10, max_length=5000)
    payload: dict = Field(default_factory=dict)


class DecisionOut(ORM):
    id: uuid.UUID
    type: str
    target_type: str
    target_id: uuid.UUID | None
    payload: dict
    justification: str
    status: str
    requested_by: UserBrief
    reviewed_by: UserBrief | None
    review_comment: str | None
    reviewed_at: datetime | None
    created_at: datetime
