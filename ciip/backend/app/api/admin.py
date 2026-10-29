import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.intake import hash_intake_token
from app.core.rbac import Perm, Role
from app.core.security import hash_password
from app.db import get_db
from app.deps import Ctx, require, scoped_get, scoped_query
from app.models import AuditLog, Organization, User
from app.schemas import (
    AuditOut,
    OrgCreate,
    OrgOut,
    OrgSettingsIn,
    Page,
    UserBrief,
    UserCreate,
    UserOut,
    UserUpdate,
)
from app.services import audit

router = APIRouter(prefix="/admin", tags=["administration"])


def _guard_role(ctx: Ctx, role: Role | str) -> None:
    if role == Role.SUPER_ADMIN and ctx.role != Role.SUPER_ADMIN:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Rôle réservé à l'opérateur de la plateforme")


@router.get("/users", response_model=list[UserOut])
def list_users(ctx: Ctx = Depends(require(Perm.USER_MANAGE)), db: Session = Depends(get_db)) -> list[User]:
    return list(db.scalars(scoped_query(User, ctx).order_by(User.full_name)).unique())


@router.get("/assignees", response_model=list[UserBrief])
def assignees(ctx: Ctx = Depends(require(Perm.INCIDENT_READ)), db: Session = Depends(get_db)) -> list[User]:
    """Light directory for assignment pickers (no e-mails, no admin fields)."""
    roles = [Role.ANALYST, Role.LEAD_ANALYST, Role.ORG_ADMIN]
    return list(db.scalars(scoped_query(User, ctx).where(User.is_active.is_(True), User.role.in_(roles))
                           .order_by(User.full_name)).unique())


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(body: UserCreate, ctx: Ctx = Depends(require(Perm.USER_MANAGE)),
                db: Session = Depends(get_db)) -> User:
    _guard_role(ctx, body.role)
    email = body.email.lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Adresse e-mail déjà utilisée")
    user = User(organization_id=ctx.org_id, email=email, full_name=body.full_name, role=body.role,
                password_hash=hash_password(body.password))
    db.add(user)
    db.flush()
    audit.record(db, "user.create", actor=ctx.user, organization_id=ctx.org_id, target_type="user",
                 target_id=user.id, ip=ctx.ip, details={"email": email, "role": body.role})
    db.commit()
    return user


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(user_id: uuid.UUID, body: UserUpdate, ctx: Ctx = Depends(require(Perm.USER_MANAGE)),
                db: Session = Depends(get_db)) -> User:
    user = scoped_get(db, User, user_id, ctx)
    changes = body.model_dump(exclude_unset=True)
    if "role" in changes:
        _guard_role(ctx, changes["role"])
        _guard_role(ctx, user.role)
    if user.id == ctx.user.id and ("role" in changes or changes.get("is_active") is False):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Impossible de modifier son propre rôle ou de se désactiver")
    before = {k: getattr(user, k) for k in changes}
    for key, value in changes.items():
        setattr(user, key, value)
    audit.record(db, "user.update", actor=ctx.user, organization_id=ctx.org_id, target_type="user",
                 target_id=user.id, ip=ctx.ip, details={"before": before, "after": changes})
    db.commit()
    return user


@router.get("/organization", response_model=OrgOut)
def get_org(ctx: Ctx = Depends(require(Perm.ORG_SETTINGS)), db: Session = Depends(get_db)) -> Organization:
    return db.get(Organization, ctx.org_id)


@router.patch("/organization", response_model=OrgOut)
def update_org(body: OrgSettingsIn, ctx: Ctx = Depends(require(Perm.ORG_SETTINGS)),
               db: Session = Depends(get_db)) -> Organization:
    org = db.get(Organization, ctx.org_id)
    changes = body.model_dump(exclude_unset=True, exclude_none=True)
    for key, value in changes.items():
        setattr(org, key, value)
    audit.record(db, "org.settings", actor=ctx.user, organization_id=ctx.org_id, target_type="organization",
                 target_id=org.id, ip=ctx.ip, details=changes)
    db.commit()
    return org


@router.post("/organization/intake-token")
def rotate_intake_token(ctx: Ctx = Depends(require(Perm.ORG_SETTINGS)), db: Session = Depends(get_db)) -> dict:
    """Issue a new webhook token for the e-mail/SMS/WhatsApp gateways. Shown once."""
    org = db.get(Organization, ctx.org_id)
    token = secrets.token_urlsafe(32)
    org.intake_token_hash = hash_intake_token(token)
    audit.record(db, "org.intake_token_rotated", actor=ctx.user, organization_id=ctx.org_id,
                 target_type="organization", target_id=org.id, ip=ctx.ip)
    db.commit()
    return {"intake_token": token, "webhook_url_template": f"/api/v1/intake/{{channel}}/{org.slug}"}


@router.get("/audit", response_model=Page[AuditOut])
def audit_logs(action: str | None = None, page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=500),
               ctx: Ctx = Depends(require(Perm.AUDIT_READ)), db: Session = Depends(get_db)) -> Page[AuditOut]:
    stmt = select(AuditLog).where(AuditLog.organization_id == ctx.org_id)
    if action:
        stmt = stmt.where(AuditLog.action.like(f"{action}%"))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(AuditLog.id.desc()).offset((page - 1) * size).limit(size))
    return Page(items=[AuditOut.model_validate(r) for r in rows], total=total, page=page, size=size)


@router.get("/audit/verify")
def verify(ctx: Ctx = Depends(require(Perm.AUDIT_READ)), db: Session = Depends(get_db)) -> dict:
    result = audit.verify_chain(db)
    audit.record(db, "audit.verify", actor=ctx.user, organization_id=ctx.org_id, ip=ctx.ip, details=result)
    db.commit()
    return result


# --- Platform operator ----------------------------------------------------

@router.get("/organizations", response_model=list[OrgOut])
def list_orgs(_: Ctx = Depends(require(Perm.ORG_MANAGE)), db: Session = Depends(get_db)) -> list[Organization]:
    return list(db.scalars(select(Organization).order_by(Organization.name)))


@router.post("/organizations", response_model=OrgOut, status_code=201)
def create_org(body: OrgCreate, ctx: Ctx = Depends(require(Perm.ORG_MANAGE)),
               db: Session = Depends(get_db)) -> Organization:
    if db.scalar(select(Organization).where((Organization.slug == body.slug) | (Organization.name == body.name))):
        raise HTTPException(status.HTTP_409_CONFLICT, "Organisation déjà existante")
    if db.scalar(select(User).where(User.email == body.admin_email.lower())):
        raise HTTPException(status.HTTP_409_CONFLICT, "Adresse e-mail déjà utilisée")
    org = Organization(name=body.name, slug=body.slug, sector=body.sector, country=body.country)
    db.add(org)
    db.flush()
    db.add(User(organization_id=org.id, email=body.admin_email.lower(), full_name=body.admin_name,
                role=Role.ORG_ADMIN, password_hash=hash_password(body.admin_password)))
    audit.record(db, "org.create", actor=ctx.user, organization_id=org.id, target_type="organization",
                 target_id=org.id, ip=ctx.ip, details={"slug": body.slug})
    db.commit()
    return org
