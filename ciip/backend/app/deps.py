"""Request-scoped dependencies: authentication, permissions, tenant scoping."""

import uuid
from dataclasses import dataclass
from typing import TypeVar

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from app.core.rbac import Perm, Role, has_perm
from app.core.security import TokenError, decode_token
from app.db import get_db
from app.models import Organization, User

_bearer = HTTPBearer(auto_error=False)

T = TypeVar("T")


@dataclass
class Ctx:
    """The authenticated principal and the organisation it acts within."""

    user: User
    org_id: uuid.UUID
    ip: str | None
    token: dict

    @property
    def role(self) -> str:
        return self.user.role

    def can(self, perm: Perm) -> bool:
        return has_perm(self.user.role, perm)


def client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def get_ctx(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> Ctx:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentification requise")
    try:
        payload = decode_token(creds.credentials, "access")
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    user = db.get(User, uuid.UUID(payload["sub"]))
    if user is None or not user.is_active or not user.organization.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Compte inactif")

    org_id = user.organization_id
    override = request.headers.get("x-organization-id")
    if override:
        # Only the platform operator may act inside another organisation.
        if user.role != Role.SUPER_ADMIN:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Changement d'organisation interdit")
        try:
            org_id = uuid.UUID(override)
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "X-Organization-Id invalide") from exc
        if db.get(Organization, org_id) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Organisation inconnue")
    return Ctx(user=user, org_id=org_id, ip=client_ip(request), token=payload)


def require(perm: Perm):
    def checker(ctx: Ctx = Depends(get_ctx)) -> Ctx:
        if not ctx.can(perm):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Permission requise : {perm.value}")
        return ctx

    return checker


def scoped_query(model: type[T], ctx: Ctx) -> Select[tuple[T]]:
    """SELECT restricted to the caller's organisation. Use for every tenant table."""
    return select(model).where(model.organization_id == ctx.org_id)  # type: ignore[attr-defined]


def scoped_get(db: Session, model: type[T], obj_id: uuid.UUID, ctx: Ctx) -> T:
    """Fetch by id within the caller's organisation; 404 otherwise (no existence leak)."""
    obj = db.get(model, obj_id)
    if obj is None or obj.organization_id != ctx.org_id:  # type: ignore[attr-defined]
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Ressource introuvable")
    return obj
