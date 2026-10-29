import hashlib
import hmac
import secrets
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.incidents import create_incident, invalidate_stats, to_detail
from app.core.config import get_settings
from app.core.kv import get_kv
from app.core.privacy import decrypt, encrypt, mask_email, mask_name, mask_phone
from app.core.rbac import Perm, Role
from app.db import get_db
from app.deps import Ctx, client_ip, require, scoped_get, scoped_query
from app.models import Category, Channel, Incident, IntakeReport, Organization
from app.schemas import (
    ConvertIn,
    IncidentCreate,
    IncidentDetail,
    IntakeIn,
    IntakeOut,
    IntakeReceipt,
    Page,
    PublicIntakeIn,
    RejectIn,
    ReporterIn,
    WebhookIntakeIn,
)
from app.services import audit
from app.services import incidents as inc_svc
from app.services.ai import rules_triage

router = APIRouter(tags=["signalements"])

_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
RECEIPT_MESSAGE = "Signalement reçu. Conservez ce code pour suivre son traitement."


def tracking_code() -> str:
    return "SIG-" + "".join(secrets.choice(_ALPHABET) for _ in range(8))


def hash_intake_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _store(db: Session, org_id: uuid.UUID, channel: str, subject: str, body: str,
           reporter: ReporterIn | None, anonymous: bool, category_hint: str | None,
           submitted_by=None) -> IntakeReport:
    r = reporter if (reporter and not anonymous) else None
    report = IntakeReport(
        organization_id=org_id,
        tracking_code=tracking_code(),
        channel=channel,
        subject=subject,
        body=body,
        # Pre-classify with the local rules engine so triage queues are sortable.
        category_hint=category_hint or rules_triage(f"{subject}\n{body}")["category"],
        reporter_name_enc=encrypt(r.name) if r else None,
        reporter_email_enc=encrypt(str(r.email)) if r and r.email else None,
        reporter_phone_enc=encrypt(r.phone) if r else None,
        is_anonymous=anonymous or r is None,
        submitted_by_id=submitted_by.id if submitted_by else None,
    )
    db.add(report)
    db.flush()
    return report


def to_out(report: IntakeReport, reveal: bool) -> IntakeOut:
    out = IntakeOut.model_validate(report)
    name, email, phone = (decrypt(report.reporter_name_enc), decrypt(report.reporter_email_enc),
                          decrypt(report.reporter_phone_enc))
    if reveal:
        out.reporter_name, out.reporter_email, out.reporter_phone, out.pii_masked = name, email, phone, False
    else:
        out.reporter_name, out.reporter_email, out.reporter_phone = mask_name(name), mask_email(email), mask_phone(phone)
    return out


# --- Authenticated channels ----------------------------------------------

@router.post("/reports", response_model=IntakeReceipt, status_code=201)
def submit(body: IntakeIn, ctx: Ctx = Depends(require(Perm.REPORT_SUBMIT)),
           db: Session = Depends(get_db)) -> IntakeReceipt:
    channel = body.channel
    # Reporters declare through the web portal; other channels are keyed in by analysts.
    if ctx.role == Role.REPORTER and channel != Channel.WEB:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Canal réservé aux analystes")
    if channel == Channel.PUBLIC_FORM:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Utilisez le formulaire public")
    report = _store(db, ctx.org_id, channel, body.subject, body.body, body.reporter, body.is_anonymous,
                    body.category_hint, submitted_by=ctx.user)
    audit.record(db, "report.submit", actor=ctx.user, organization_id=ctx.org_id,
                 target_type="report", target_id=report.id, ip=ctx.ip, details={"channel": channel})
    db.commit()
    invalidate_stats(ctx.org_id)
    return IntakeReceipt(tracking_code=report.tracking_code, status=report.status, message=RECEIPT_MESSAGE)


@router.get("/reports", response_model=Page[IntakeOut])
def list_reports(
    status_: str | None = Query(default=None, alias="status"),
    channel: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(25, ge=1, le=200),
    ctx: Ctx = Depends(require(Perm.REPORT_SUBMIT)),
    db: Session = Depends(get_db),
) -> Page[IntakeOut]:
    stmt = scoped_query(IntakeReport, ctx)
    if not ctx.can(Perm.REPORT_TRIAGE):
        stmt = stmt.where(IntakeReport.submitted_by_id == ctx.user.id)
    if status_:
        stmt = stmt.where(IntakeReport.status == status_)
    if channel:
        stmt = stmt.where(IntakeReport.channel == channel)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(IntakeReport.created_at.desc()).offset((page - 1) * size).limit(size))
    return Page(items=[to_out(r, False) for r in rows], total=total, page=page, size=size)


@router.get("/reports/{report_id}", response_model=IntakeOut)
def get_report(report_id: uuid.UUID, reveal: bool = False, ctx: Ctx = Depends(require(Perm.REPORT_SUBMIT)),
               db: Session = Depends(get_db)) -> IntakeOut:
    report = scoped_get(db, IntakeReport, report_id, ctx)
    if not ctx.can(Perm.REPORT_TRIAGE) and report.submitted_by_id != ctx.user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Ressource introuvable")
    if reveal:
        if not ctx.can(Perm.PII_READ):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Permission requise : pii:read")
        audit.record(db, "pii.read", actor=ctx.user, organization_id=ctx.org_id,
                     target_type="report", target_id=report.id, ip=ctx.ip)
        db.commit()
    return to_out(report, reveal)


@router.post("/reports/{report_id}/convert", response_model=IncidentDetail)
def convert(report_id: uuid.UUID, body: ConvertIn, ctx: Ctx = Depends(require(Perm.REPORT_TRIAGE)),
            db: Session = Depends(get_db)) -> IncidentDetail:
    report = scoped_get(db, IntakeReport, report_id, ctx)
    if report.status != "received":
        raise HTTPException(status.HTTP_409_CONFLICT, "Signalement déjà traité")
    if body.merge_into_incident_id:
        inc = scoped_get(db, Incident, body.merge_into_incident_id, ctx)
        inc_svc.add_event(db, inc, ctx.user, "report_merged",
                          f"Signalement {report.tracking_code} rattaché : {report.subject}",
                          tracking_code=report.tracking_code, channel=report.channel)
        action = "report.merge"
    else:
        inc = create_incident(db, ctx, IncidentCreate(
            title=body.title or report.subject,
            description=report.body,
            category=body.category or Category(report.category_hint or Category.OTHER),
            severity=body.severity,
            source_channel=Channel(report.channel),
        ))
        inc_svc.add_event(db, inc, ctx.user, "report_merged",
                          f"Créé depuis le signalement {report.tracking_code}",
                          tracking_code=report.tracking_code, channel=report.channel)
        action = "report.convert"
    report.status = "converted"
    report.incident_id = inc.id
    report.triaged_by_id = ctx.user.id
    audit.record(db, action, actor=ctx.user, organization_id=ctx.org_id, target_type="report",
                 target_id=report.id, ip=ctx.ip, details={"incident": inc.reference})
    db.commit()
    db.refresh(inc)
    return to_detail(db, inc)


@router.post("/reports/{report_id}/reject", response_model=IntakeOut)
def reject(report_id: uuid.UUID, body: RejectIn, ctx: Ctx = Depends(require(Perm.REPORT_TRIAGE)),
           db: Session = Depends(get_db)) -> IntakeOut:
    report = scoped_get(db, IntakeReport, report_id, ctx)
    if report.status != "received":
        raise HTTPException(status.HTTP_409_CONFLICT, "Signalement déjà traité")
    report.status = "rejected"
    report.rejection_reason = body.reason
    report.triaged_by_id = ctx.user.id
    audit.record(db, "report.reject", actor=ctx.user, organization_id=ctx.org_id, target_type="report",
                 target_id=report.id, ip=ctx.ip, details={"reason": body.reason})
    db.commit()
    invalidate_stats(ctx.org_id)
    return to_out(report, False)


# --- Public, anonymous portal --------------------------------------------

def _org_by_slug(db: Session, slug: str) -> Organization:
    org = db.scalar(select(Organization).where(Organization.slug == slug, Organization.is_active.is_(True)))
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organisation inconnue")
    return org


def _rate_limit(request: Request, bucket: str) -> None:
    ip = client_ip(request) or "unknown"
    limit = get_settings().public_rate_limit_per_hour
    if get_kv().incr(f"rl:{bucket}:{ip}", 3600) > limit:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Trop de signalements depuis cette adresse")


@router.get("/public/organizations/{slug}")
def public_org(slug: str, db: Session = Depends(get_db)) -> dict:
    org = _org_by_slug(db, slug)
    return {"name": org.name, "slug": org.slug, "categories": [c.value for c in Category]}


@router.post("/public/{slug}/reports", response_model=IntakeReceipt, status_code=201)
def public_submit(slug: str, body: PublicIntakeIn, request: Request,
                  db: Session = Depends(get_db)) -> IntakeReceipt:
    _rate_limit(request, "public")
    org = _org_by_slug(db, slug)
    if body.website:  # honeypot: pretend success, store nothing
        return IntakeReceipt(tracking_code=tracking_code(), status="received", message=RECEIPT_MESSAGE)
    anonymous = body.reporter is None or not any([body.reporter.name, body.reporter.email, body.reporter.phone])
    report = _store(db, org.id, Channel.PUBLIC_FORM, body.subject, body.body, body.reporter, anonymous,
                    body.category_hint)
    # The submitter's IP is not stored on the report itself (anonymity) — only in the audit trail.
    audit.record(db, "report.public_submit", organization_id=org.id, target_type="report",
                 target_id=report.id, ip=client_ip(request))
    db.commit()
    invalidate_stats(org.id)
    return IntakeReceipt(tracking_code=report.tracking_code, status=report.status, message=RECEIPT_MESSAGE)


_PUBLIC_STATUS = {
    "received": "Reçu — en attente d'analyse",
    "converted": "Pris en charge par l'équipe de réponse",
    "rejected": "Clôturé sans suite",
}


@router.get("/public/reports/{code}")
def public_status(code: str, request: Request, db: Session = Depends(get_db)) -> dict:
    _rate_limit(request, "lookup")
    report = db.scalar(select(IntakeReport).where(IntakeReport.tracking_code == code.upper()))
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Code de suivi inconnu")
    return {"tracking_code": report.tracking_code, "status": report.status,
            "label": _PUBLIC_STATUS.get(report.status, report.status), "received_at": report.created_at}


# --- Gateway webhooks (e-mail, SMS, WhatsApp) -----------------------------

WEBHOOK_CHANNELS = {Channel.EMAIL, Channel.SMS, Channel.WHATSAPP}


@router.post("/intake/{channel}/{slug}", response_model=IntakeReceipt, status_code=201)
def webhook(channel: Channel, slug: str, body: WebhookIntakeIn, request: Request,
            x_intake_token: str = Header(default=""), db: Session = Depends(get_db)) -> IntakeReceipt:
    if channel not in WEBHOOK_CHANNELS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Canal non pris en charge")
    org = _org_by_slug(db, slug)
    if not org.intake_token_hash or not hmac.compare_digest(org.intake_token_hash, hash_intake_token(x_intake_token)):
        audit.record(db, "intake.token_rejected", organization_id=org.id, ip=client_ip(request),
                     details={"channel": channel})
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Jeton d'ingestion invalide")
    try:
        reporter = ReporterIn(email=body.sender) if channel == Channel.EMAIL else ReporterIn(phone=body.sender[:40])
    except ValidationError:
        reporter = ReporterIn(name=body.sender[:200])
    subject = body.subject or f"Signalement {channel.value} — {body.body[:60]}"
    report = _store(db, org.id, channel, subject[:300], body.body, reporter, False, None)
    audit.record(db, "report.webhook", organization_id=org.id, target_type="report",
                 target_id=report.id, ip=client_ip(request), details={"channel": channel})
    db.commit()
    invalidate_stats(org.id)
    return IntakeReceipt(tracking_code=report.tracking_code, status=report.status, message=RECEIPT_MESSAGE)
