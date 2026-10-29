from datetime import datetime, timedelta

from fastapi import HTTPException, status
from sqlalchemy import update
from sqlalchemy.orm import Session

from app.models import (
    EscalationLevel,
    Incident,
    IncidentEvent,
    Organization,
    Severity,
    aware,
    utcnow,
)
from app.models import (
    IncidentStatus as S,
)

# (acknowledge within, resolve within)
SLA: dict[str, tuple[timedelta, timedelta]] = {
    Severity.CRITICAL: (timedelta(minutes=15), timedelta(hours=4)),
    Severity.HIGH: (timedelta(hours=1), timedelta(hours=24)),
    Severity.MEDIUM: (timedelta(hours=4), timedelta(hours=72)),
    Severity.LOW: (timedelta(hours=24), timedelta(days=7)),
}

ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    S.NEW: {S.TRIAGED, S.IN_PROGRESS, S.REJECTED},
    S.TRIAGED: {S.IN_PROGRESS, S.REJECTED},
    S.IN_PROGRESS: {S.CONTAINED, S.RESOLVED},
    S.CONTAINED: {S.IN_PROGRESS, S.RESOLVED},
    S.RESOLVED: {S.CLOSED, S.IN_PROGRESS},
    S.CLOSED: {S.IN_PROGRESS},
    S.REJECTED: {S.TRIAGED},
}

OPEN_STATUSES = {S.NEW, S.TRIAGED, S.IN_PROGRESS, S.CONTAINED}

ESCALATION_ORDER = [EscalationLevel.L1, EscalationLevel.L2, EscalationLevel.L3, EscalationLevel.EXTERNAL]


def next_reference(db: Session, org_id, now: datetime | None = None) -> str:
    """Atomically bump the per-organisation counter: INC-2026-0001."""
    seq = db.execute(
        update(Organization)
        .where(Organization.id == org_id)
        .values(incident_seq=Organization.incident_seq + 1)
        .returning(Organization.incident_seq)
    ).scalar_one()
    year = (now or utcnow()).year
    return f"INC-{year}-{seq:04d}"


def apply_sla(incident: Incident, base: datetime | None = None) -> None:
    ack, resolve = SLA[incident.severity]
    start = aware(base or incident.created_at) or utcnow()
    incident.sla_ack_due = start + ack
    incident.sla_resolve_due = start + resolve


def is_sla_breached(incident: Incident, now: datetime | None = None) -> bool:
    now = now or utcnow()
    ack_due, resolve_due = aware(incident.sla_ack_due), aware(incident.sla_resolve_due)
    acked, resolved = aware(incident.acknowledged_at), aware(incident.resolved_at)
    if ack_due and (acked or now) > ack_due:
        return True
    if resolve_due and incident.status not in (S.REJECTED,) and (resolved or now) > resolve_due:
        return True
    return False


def add_event(db: Session, incident: Incident, actor, kind: str, message: str = "", **data) -> IncidentEvent:
    event = IncidentEvent(
        incident_id=incident.id,
        organization_id=incident.organization_id,
        actor_id=actor.id if actor else None,
        kind=kind,
        message=message,
        data=data,
    )
    db.add(event)
    return event


def check_transition(current: str, target: str) -> None:
    if target not in ALLOWED_TRANSITIONS.get(current, set()):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Transition {current} → {target} non autorisée",
        )


def needs_approval_to_close(incident: Incident, target: str) -> bool:
    return target == S.CLOSED and incident.severity == Severity.CRITICAL


def apply_status(incident: Incident, target: str) -> None:
    now = utcnow()
    if target in (S.TRIAGED, S.IN_PROGRESS) and incident.acknowledged_at is None:
        incident.acknowledged_at = now
    if target == S.RESOLVED:
        incident.resolved_at = now
    if target == S.CLOSED:
        incident.closed_at = now
        if incident.resolved_at is None:
            incident.resolved_at = now
    if target == S.IN_PROGRESS:
        incident.closed_at = None
        if incident.status in (S.RESOLVED, S.CLOSED):
            incident.resolved_at = None
    incident.status = target
