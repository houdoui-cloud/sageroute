import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.incidents import invalidate_stats
from app.core.rbac import Perm
from app.db import get_db
from app.deps import Ctx, require, scoped_get, scoped_query
from app.models import DecisionRequest, utcnow
from app.schemas import DecisionIn, DecisionOut, ReviewIn
from app.services import audit
from app.services import decisions as svc

router = APIRouter(prefix="/decisions", tags=["décisions"])


@router.get("/types")
def types(_: Ctx = Depends(require(Perm.DECISION_REQUEST))) -> list[dict]:
    return [{"type": k, "target_type": t, "label": label} for k, (t, label) in svc.DECISION_TYPES.items()]


@router.get("", response_model=list[DecisionOut])
def list_decisions(status_: str | None = None, ctx: Ctx = Depends(require(Perm.DECISION_REQUEST)),
                   db: Session = Depends(get_db)) -> list[DecisionRequest]:
    stmt = scoped_query(DecisionRequest, ctx)
    if status_:
        stmt = stmt.where(DecisionRequest.status == status_)
    return list(db.scalars(stmt.order_by(DecisionRequest.created_at.desc()).limit(200)).unique())


@router.post("", response_model=DecisionOut, status_code=201)
def request_decision(body: DecisionIn, ctx: Ctx = Depends(require(Perm.DECISION_REQUEST)),
                     db: Session = Depends(get_db)) -> DecisionRequest:
    if body.type not in svc.DECISION_TYPES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Type de décision inconnu")
    if body.type == "purge_data" and not ctx.can(Perm.ORG_SETTINGS):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Seul un administrateur peut demander une purge")
    target = svc.load_target(db, body.type, body.target_id, ctx.org_id)
    svc.precheck(db, body.type, target)
    duplicate = db.scalar(scoped_query(DecisionRequest, ctx).where(
        DecisionRequest.type == body.type, DecisionRequest.target_id == target.id,
        DecisionRequest.status == "pending"))
    if duplicate:
        raise HTTPException(status.HTTP_409_CONFLICT, "Une demande identique est déjà en attente")
    d = DecisionRequest(organization_id=ctx.org_id, type=body.type, target_type=svc.DECISION_TYPES[body.type][0],
                        target_id=target.id, payload=body.payload, justification=body.justification,
                        requested_by_id=ctx.user.id)
    db.add(d)
    db.flush()
    audit.record(db, "decision.request", actor=ctx.user, organization_id=ctx.org_id, target_type="decision",
                 target_id=d.id, ip=ctx.ip, details={"type": body.type, "target_id": target.id})
    db.commit()
    db.refresh(d)
    return d


@router.post("/{decision_id}/review", response_model=DecisionOut)
def review(decision_id: uuid.UUID, body: ReviewIn, ctx: Ctx = Depends(require(Perm.DECISION_APPROVE)),
           db: Session = Depends(get_db)) -> DecisionRequest:
    d = scoped_get(db, DecisionRequest, decision_id, ctx)
    if d.status != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, "Décision déjà examinée")
    if d.requested_by_id == ctx.user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "Principe des quatre yeux : le demandeur ne peut pas approuver sa propre demande")
    result: dict = {}
    if body.approve:
        result = svc.execute(db, d, ctx.user)
    d.status = "approved" if body.approve else "rejected"
    d.reviewed_by_id = ctx.user.id
    d.review_comment = body.comment
    d.reviewed_at = utcnow()
    audit.record(db, "decision.approve" if body.approve else "decision.reject", actor=ctx.user,
                 organization_id=ctx.org_id, target_type="decision", target_id=d.id, ip=ctx.ip,
                 details={"type": d.type, "result": result, "comment": body.comment})
    db.commit()
    invalidate_stats(ctx.org_id)
    db.refresh(d)
    return d
