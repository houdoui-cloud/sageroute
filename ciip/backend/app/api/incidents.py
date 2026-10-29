import csv
import io
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.kv import get_kv
from app.core.rbac import Perm
from app.db import get_db
from app.deps import Ctx, require, scoped_get, scoped_query
from app.models import (
    DecisionRequest,
    Escalation,
    EscalationLevel,
    Incident,
    IncidentStatus,
    Playbook,
    User,
)
from app.schemas import (
    AssignIn,
    CommentIn,
    EscalateIn,
    EventOut,
    IncidentCreate,
    IncidentDetail,
    IncidentOut,
    IncidentUpdate,
    IocBrief,
    Page,
    StatusChange,
)
from app.services import audit
from app.services import incidents as svc

router = APIRouter(prefix="/incidents", tags=["incidents"])


def invalidate_stats(org_id) -> None:
    get_kv().delete_prefix(f"stats:{org_id}")


def to_out(inc: Incident) -> IncidentOut:
    out = IncidentOut.model_validate(inc)
    out.sla_breached = svc.is_sla_breached(inc)
    return out


def to_detail(db: Session, inc: Incident) -> IncidentDetail:
    pending = db.scalar(select(func.count()).select_from(DecisionRequest).where(
        DecisionRequest.organization_id == inc.organization_id,
        DecisionRequest.target_id == inc.id, DecisionRequest.status == "pending")) or 0
    return IncidentDetail(
        **to_out(inc).model_dump(),
        events=[EventOut.model_validate(e) for e in inc.events],
        iocs=[IocBrief.model_validate(i) for i in inc.iocs],
        pending_decisions=pending,
    )


def _check_assignee(db: Session, ctx: Ctx, assignee_id: uuid.UUID | None) -> User | None:
    if assignee_id is None:
        return None
    user = db.get(User, assignee_id)
    if user is None or user.organization_id != ctx.org_id or not user.is_active:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Assigné inconnu dans cette organisation")
    return user


def create_incident(db: Session, ctx: Ctx, body: IncidentCreate) -> Incident:
    """Shared by the incidents API and report conversion."""
    _check_assignee(db, ctx, body.assignee_id)
    inc = Incident(
        organization_id=ctx.org_id,
        reference=svc.next_reference(db, ctx.org_id),
        title=body.title,
        description=body.description,
        category=body.category,
        severity=body.severity,
        source_channel=body.source_channel,
        affected_assets=body.affected_assets,
        tags=body.tags,
        assignee_id=body.assignee_id,
        created_by_id=ctx.user.id,
    )
    db.add(inc)
    db.flush()
    svc.apply_sla(inc)
    svc.add_event(db, inc, ctx.user, "created", f"Incident créé ({inc.severity})")
    audit.record(db, "incident.create", actor=ctx.user, organization_id=ctx.org_id,
                 target_type="incident", target_id=inc.id, ip=ctx.ip,
                 details={"reference": inc.reference, "severity": inc.severity})
    invalidate_stats(ctx.org_id)
    return inc


@router.get("", response_model=Page[IncidentOut])
def list_incidents(
    status_: list[IncidentStatus] | None = Query(default=None, alias="status"),
    severity: list[str] | None = Query(default=None),
    category: str | None = None,
    assignee_id: uuid.UUID | None = None,
    q: str | None = Query(default=None, max_length=200),
    open_only: bool = False,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(25, ge=1, le=200),
    ctx: Ctx = Depends(require(Perm.INCIDENT_READ)),
    db: Session = Depends(get_db),
) -> Page[IncidentOut]:
    stmt = scoped_query(Incident, ctx)
    if status_:
        stmt = stmt.where(Incident.status.in_(status_))
    if open_only:
        stmt = stmt.where(Incident.status.in_(svc.OPEN_STATUSES))
    if severity:
        stmt = stmt.where(Incident.severity.in_(severity))
    if category:
        stmt = stmt.where(Incident.category == category)
    if assignee_id:
        stmt = stmt.where(Incident.assignee_id == assignee_id)
    if created_from:
        stmt = stmt.where(Incident.created_at >= created_from)
    if created_to:
        stmt = stmt.where(Incident.created_at <= created_to)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Incident.title.ilike(like), Incident.reference.ilike(like),
                              Incident.description.ilike(like)))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(Incident.created_at.desc()).offset((page - 1) * size).limit(size)).unique()
    return Page(items=[to_out(i) for i in rows], total=total, page=page, size=size)


@router.post("", response_model=IncidentDetail, status_code=201)
def create(body: IncidentCreate, ctx: Ctx = Depends(require(Perm.INCIDENT_WRITE)),
           db: Session = Depends(get_db)) -> IncidentDetail:
    inc = create_incident(db, ctx, body)
    db.commit()
    db.refresh(inc)
    return to_detail(db, inc)


@router.get("/export.csv")
def export_csv(ctx: Ctx = Depends(require(Perm.REPORTS_READ)), db: Session = Depends(get_db)) -> StreamingResponse:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["reference", "titre", "categorie", "severite", "statut", "canal", "escalade",
                "cree_le", "pris_en_charge_le", "resolu_le", "sla_depasse"])
    for i in db.scalars(scoped_query(Incident, ctx).order_by(Incident.created_at)).unique():
        w.writerow([i.reference, i.title, i.category, i.severity, i.status, i.source_channel,
                    i.escalation_level, i.created_at, i.acknowledged_at or "", i.resolved_at or "",
                    "oui" if svc.is_sla_breached(i) else "non"])
    audit.record(db, "incident.export", actor=ctx.user, organization_id=ctx.org_id, ip=ctx.ip)
    db.commit()
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="incidents.csv"'})


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: uuid.UUID, ctx: Ctx = Depends(require(Perm.INCIDENT_READ)),
                 db: Session = Depends(get_db)) -> IncidentDetail:
    return to_detail(db, scoped_get(db, Incident, incident_id, ctx))


@router.patch("/{incident_id}", response_model=IncidentDetail)
def update(incident_id: uuid.UUID, body: IncidentUpdate, ctx: Ctx = Depends(require(Perm.INCIDENT_WRITE)),
           db: Session = Depends(get_db)) -> IncidentDetail:
    inc = scoped_get(db, Incident, incident_id, ctx)
    changes = body.model_dump(exclude_unset=True)
    if "playbook_id" in changes and changes["playbook_id"] is not None:
        pb = db.get(Playbook, changes["playbook_id"])
        if pb is None or pb.organization_id not in (None, ctx.org_id) or pb.status != "active":
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Playbook indisponible")
    before = {k: getattr(inc, k) for k in changes}
    for key, value in changes.items():
        setattr(inc, key, value)
    if "severity" in changes and changes["severity"] != before["severity"]:
        svc.apply_sla(inc)
        svc.add_event(db, inc, ctx.user, "severity_change", "Sévérité modifiée",
                      **{"from": before["severity"], "to": inc.severity})
    if changes:
        svc.add_event(db, inc, ctx.user, "updated", "Champs modifiés : " + ", ".join(changes))
        audit.record(db, "incident.update", actor=ctx.user, organization_id=ctx.org_id,
                     target_type="incident", target_id=inc.id, ip=ctx.ip,
                     details={"fields": list(changes), "before": before})
    db.commit()
    invalidate_stats(ctx.org_id)
    db.refresh(inc)
    return to_detail(db, inc)


@router.post("/{incident_id}/status", response_model=IncidentDetail)
def change_status(incident_id: uuid.UUID, body: StatusChange, ctx: Ctx = Depends(require(Perm.INCIDENT_WRITE)),
                  db: Session = Depends(get_db)) -> IncidentDetail:
    inc = scoped_get(db, Incident, incident_id, ctx)
    svc.check_transition(inc.status, body.status)
    if svc.needs_approval_to_close(inc, body.status):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "La clôture d'un incident critique est une décision sensible : "
            "créez une demande « close_critical_incident » à faire approuver.",
        )
    old = inc.status
    svc.apply_status(inc, body.status)
    svc.add_event(db, inc, ctx.user, "status_change", body.comment, **{"from": old, "to": body.status.value})
    audit.record(db, "incident.status", actor=ctx.user, organization_id=ctx.org_id,
                 target_type="incident", target_id=inc.id, ip=ctx.ip,
                 details={"from": old, "to": body.status.value})
    db.commit()
    invalidate_stats(ctx.org_id)
    db.refresh(inc)
    return to_detail(db, inc)


@router.post("/{incident_id}/assign", response_model=IncidentDetail)
def assign(incident_id: uuid.UUID, body: AssignIn, ctx: Ctx = Depends(require(Perm.INCIDENT_WRITE)),
           db: Session = Depends(get_db)) -> IncidentDetail:
    inc = scoped_get(db, Incident, incident_id, ctx)
    user = _check_assignee(db, ctx, body.assignee_id)
    inc.assignee_id = body.assignee_id
    svc.add_event(db, inc, ctx.user, "assignment",
                  f"Assigné à {user.full_name}" if user else "Désassigné",
                  assignee_id=str(body.assignee_id) if body.assignee_id else None)
    audit.record(db, "incident.assign", actor=ctx.user, organization_id=ctx.org_id,
                 target_type="incident", target_id=inc.id, ip=ctx.ip,
                 details={"assignee_id": body.assignee_id})
    db.commit()
    db.refresh(inc)
    return to_detail(db, inc)


@router.post("/{incident_id}/comments", response_model=IncidentDetail, status_code=201)
def comment(incident_id: uuid.UUID, body: CommentIn, ctx: Ctx = Depends(require(Perm.INCIDENT_WRITE)),
            db: Session = Depends(get_db)) -> IncidentDetail:
    inc = scoped_get(db, Incident, incident_id, ctx)
    svc.add_event(db, inc, ctx.user, "comment", body.message)
    audit.record(db, "incident.comment", actor=ctx.user, organization_id=ctx.org_id,
                 target_type="incident", target_id=inc.id, ip=ctx.ip)
    db.commit()
    db.refresh(inc)
    return to_detail(db, inc)


@router.post("/{incident_id}/escalate", response_model=IncidentDetail)
def escalate(incident_id: uuid.UUID, body: EscalateIn, ctx: Ctx = Depends(require(Perm.INCIDENT_ESCALATE)),
             db: Session = Depends(get_db)) -> IncidentDetail:
    inc = scoped_get(db, Incident, incident_id, ctx)
    if body.to_level == EscalationLevel.EXTERNAL:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "L'escalade externe (CERT national) est une décision sensible : "
            "créez une demande « external_escalation » à faire approuver.",
        )
    order = svc.ESCALATION_ORDER
    if order.index(EscalationLevel(body.to_level)) <= order.index(EscalationLevel(inc.escalation_level)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Le niveau cible doit être supérieur au niveau actuel")
    db.add(Escalation(incident_id=inc.id, organization_id=ctx.org_id, from_level=inc.escalation_level,
                      to_level=body.to_level, reason=body.reason, escalated_by_id=ctx.user.id))
    old = inc.escalation_level
    inc.escalation_level = body.to_level
    svc.add_event(db, inc, ctx.user, "escalation", body.reason, **{"from": old, "to": body.to_level.value})
    audit.record(db, "incident.escalate", actor=ctx.user, organization_id=ctx.org_id,
                 target_type="incident", target_id=inc.id, ip=ctx.ip,
                 details={"from": old, "to": body.to_level.value})
    db.commit()
    db.refresh(inc)
    return to_detail(db, inc)


@router.get("/{incident_id}/escalations")
def list_escalations(incident_id: uuid.UUID, ctx: Ctx = Depends(require(Perm.INCIDENT_READ)),
                     db: Session = Depends(get_db)) -> list[dict]:
    scoped_get(db, Incident, incident_id, ctx)
    rows = db.scalars(scoped_query(Escalation, ctx).where(Escalation.incident_id == incident_id)
                      .order_by(Escalation.created_at))
    return [{"from_level": e.from_level, "to_level": e.to_level, "reason": e.reason,
             "created_at": e.created_at} for e in rows]

