import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.incidents import invalidate_stats
from app.core.rbac import Perm
from app.db import get_db
from app.deps import Ctx, require, scoped_get, scoped_query
from app.models import AiSuggestion, Category, Incident, Playbook, Severity, utcnow
from app.schemas import (
    AskIn,
    PlaybookGenIn,
    PlaybookIn,
    PlaybookOut,
    ReviewIn,
    SuggestionOut,
    TriageIn,
)
from app.services import ai as engine
from app.services import audit
from app.services import incidents as inc_svc

router = APIRouter(tags=["assistant IA"])


def _incident_context(inc: Incident) -> str:
    return (f"Référence : {inc.reference}\nTitre : {inc.title}\nCatégorie : {inc.category}\n"
            f"Sévérité : {inc.severity}\nStatut : {inc.status}\nDescription : {inc.description}")


def _save(db: Session, ctx: Ctx, kind: str, result: engine.AiResult, incident_id: uuid.UUID | None,
          status_: str = "proposed") -> AiSuggestion:
    s = AiSuggestion(organization_id=ctx.org_id, incident_id=incident_id, kind=kind, engine=result.engine,
                     prompt_redacted=result.prompt_redacted[:20000], output=result.output,
                     confidence=result.confidence, status=status_, requested_by_id=ctx.user.id)
    db.add(s)
    db.flush()
    audit.record(db, f"ai.{kind}", actor=ctx.user, organization_id=ctx.org_id, target_type="ai_suggestion",
                 target_id=s.id, ip=ctx.ip, details={"engine": result.engine, "incident_id": incident_id})
    db.commit()
    return s


@router.get("/ai/status")
def ai_status(_: Ctx = Depends(require(Perm.AI_USE))) -> dict:
    return engine.ollama_status()


@router.post("/ai/triage", response_model=SuggestionOut, status_code=201)
def triage(body: TriageIn, ctx: Ctx = Depends(require(Perm.AI_USE)), db: Session = Depends(get_db)) -> AiSuggestion:
    if body.incident_id:
        inc = scoped_get(db, Incident, body.incident_id, ctx)
        text = f"{inc.title}\n{inc.description}"
    elif body.text:
        text = body.text
    else:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Fournir incident_id ou text")
    return _save(db, ctx, "triage", engine.triage(text), body.incident_id,
                 # Free-text triage is advisory only: nothing to apply it to.
                 "proposed" if body.incident_id else "informational")


@router.post("/ai/playbook", response_model=SuggestionOut, status_code=201)
def gen_playbook(body: PlaybookGenIn, ctx: Ctx = Depends(require(Perm.AI_USE)),
                 db: Session = Depends(get_db)) -> AiSuggestion:
    context = body.context
    if body.incident_id:
        context = _incident_context(scoped_get(db, Incident, body.incident_id, ctx)) + "\n" + context
    return _save(db, ctx, "playbook", engine.generate_playbook(body.category, context), body.incident_id)


@router.post("/ai/ask", response_model=SuggestionOut, status_code=201)
def ask(body: AskIn, ctx: Ctx = Depends(require(Perm.AI_USE)), db: Session = Depends(get_db)) -> AiSuggestion:
    context = _incident_context(scoped_get(db, Incident, body.incident_id, ctx)) if body.incident_id else ""
    return _save(db, ctx, "answer", engine.answer(body.question, context), body.incident_id, "informational")


@router.get("/ai/suggestions", response_model=list[SuggestionOut])
def list_suggestions(incident_id: uuid.UUID | None = None, status_: str | None = None,
                     ctx: Ctx = Depends(require(Perm.AI_USE)), db: Session = Depends(get_db)) -> list[AiSuggestion]:
    stmt = scoped_query(AiSuggestion, ctx)
    if incident_id:
        stmt = stmt.where(AiSuggestion.incident_id == incident_id)
    if status_:
        stmt = stmt.where(AiSuggestion.status == status_)
    return list(db.scalars(stmt.order_by(AiSuggestion.created_at.desc()).limit(100)))


@router.post("/ai/suggestions/{suggestion_id}/review", response_model=SuggestionOut)
def review(suggestion_id: uuid.UUID, body: ReviewIn, ctx: Ctx = Depends(require(Perm.AI_VALIDATE)),
           db: Session = Depends(get_db)) -> AiSuggestion:
    """Human-in-the-loop gate: a cleared analyst accepts or rejects an AI proposal."""
    s = scoped_get(db, AiSuggestion, suggestion_id, ctx)
    if s.status != "proposed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Suggestion déjà examinée ou non applicable")
    applied: dict = {}
    if body.approve:
        if s.kind == "triage" and s.incident_id:
            inc = scoped_get(db, Incident, s.incident_id, ctx)
            before = {"category": inc.category, "severity": inc.severity}
            inc.category = Category(s.output["category"])
            new_sev = Severity(s.output["severity"])
            if new_sev != inc.severity:
                inc.severity = new_sev
                inc_svc.apply_sla(inc)
            pb_name = s.output.get("recommended_playbook")
            if pb_name and inc.playbook_id is None:
                pb = db.scalar(select(Playbook).where(Playbook.name == pb_name, Playbook.organization_id.is_(None)))
                inc.playbook_id = pb.id if pb else None
            inc_svc.add_event(db, inc, ctx.user, "ai_validated",
                              f"Triage IA validé : {inc.category} / {inc.severity}",
                              suggestion_id=str(s.id), before=before)
            applied = {"incident": inc.reference, "before": before,
                       "after": {"category": inc.category, "severity": inc.severity}}
            invalidate_stats(ctx.org_id)
        elif s.kind == "playbook":
            pb = Playbook(organization_id=ctx.org_id, name=s.output["name"][:200], category=s.output["category"],
                          description=s.output.get("description", ""), steps=s.output["steps"], status="active",
                          generated_by_ai=True, validated_by_id=ctx.user.id)
            db.add(pb)
            db.flush()
            applied = {"playbook_id": str(pb.id)}
    s.status = "validated" if body.approve else "rejected"
    s.reviewed_by_id = ctx.user.id
    s.review_comment = body.comment
    s.reviewed_at = utcnow()
    audit.record(db, "ai.review", actor=ctx.user, organization_id=ctx.org_id, target_type="ai_suggestion",
                 target_id=s.id, ip=ctx.ip, details={"approved": body.approve, "applied": applied})
    db.commit()
    return s


# --- Playbooks ------------------------------------------------------------

@router.get("/playbooks", response_model=list[PlaybookOut])
def list_playbooks(category: str | None = None, ctx: Ctx = Depends(require(Perm.INCIDENT_READ)),
                   db: Session = Depends(get_db)) -> list[Playbook]:
    stmt = select(Playbook).where(or_(Playbook.organization_id == ctx.org_id, Playbook.organization_id.is_(None)),
                                  Playbook.status == "active")
    if category:
        stmt = stmt.where(Playbook.category == category)
    return list(db.scalars(stmt.order_by(Playbook.organization_id.is_(None), Playbook.name)))


@router.get("/playbooks/{playbook_id}", response_model=PlaybookOut)
def get_playbook(playbook_id: uuid.UUID, ctx: Ctx = Depends(require(Perm.INCIDENT_READ)),
                 db: Session = Depends(get_db)) -> Playbook:
    pb = db.get(Playbook, playbook_id)
    if pb is None or pb.organization_id not in (None, ctx.org_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Ressource introuvable")
    return pb


@router.post("/playbooks", response_model=PlaybookOut, status_code=201)
def create_playbook(body: PlaybookIn, ctx: Ctx = Depends(require(Perm.PLAYBOOK_WRITE)),
                    db: Session = Depends(get_db)) -> Playbook:
    pb = Playbook(organization_id=ctx.org_id, name=body.name, category=body.category,
                  description=body.description, steps=body.steps, validated_by_id=ctx.user.id)
    db.add(pb)
    db.flush()
    audit.record(db, "playbook.create", actor=ctx.user, organization_id=ctx.org_id, target_type="playbook",
                 target_id=pb.id, ip=ctx.ip)
    db.commit()
    return pb


@router.post("/playbooks/{playbook_id}/archive", response_model=PlaybookOut)
def archive_playbook(playbook_id: uuid.UUID, ctx: Ctx = Depends(require(Perm.PLAYBOOK_WRITE)),
                     db: Session = Depends(get_db)) -> Playbook:
    pb = scoped_get(db, Playbook, playbook_id, ctx)  # reference playbooks are read-only
    pb.status = "archived"
    audit.record(db, "playbook.archive", actor=ctx.user, organization_id=ctx.org_id, target_type="playbook",
                 target_id=pb.id, ip=ctx.ip)
    db.commit()
    return pb
