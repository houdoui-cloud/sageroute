import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.kv import get_kv
from app.core.rbac import permissions_for
from app.core.security import (
    DUMMY_HASH,
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    revoke_token,
    verify_password,
)
from app.db import get_db
from app.deps import Ctx, client_ip, get_ctx
from app.models import User, aware, utcnow
from app.schemas import LoginIn, MeOut, OrgOut, PasswordChangeIn, RefreshIn, TokenPair
from app.services import audit

router = APIRouter(prefix="/auth", tags=["auth"])


def _tokens(user: User) -> TokenPair:
    return TokenPair(
        access_token=create_access_token(user.id, user.organization_id, user.role),
        refresh_token=create_refresh_token(user.id),
        expires_in=get_settings().access_token_minutes * 60,
    )


@router.post("/login", response_model=TokenPair)
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)) -> TokenPair:
    s = get_settings()
    ip = client_ip(request)
    # Per-IP throttle on top of per-account lockout.
    if get_kv().incr(f"rl:login:{ip}", 900) > 50:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Trop de tentatives, réessayez plus tard")

    user = db.scalar(select(User).where(User.email == body.email.lower()))
    generic = HTTPException(status.HTTP_401_UNAUTHORIZED, "Identifiants invalides")
    if user is None:
        verify_password(body.password, DUMMY_HASH)  # constant-time-ish
        audit.record(db, "auth.login_failed", ip=ip, details={"email": body.email.lower(), "reason": "unknown"})
        db.commit()
        raise generic

    now = utcnow()
    if user.locked_until and aware(user.locked_until) > now:
        audit.record(db, "auth.login_blocked", actor=user, ip=ip)
        db.commit()
        raise HTTPException(status.HTTP_423_LOCKED, "Compte temporairement verrouillé")

    if not verify_password(body.password, user.password_hash) or not user.is_active:
        user.failed_logins += 1
        details = {"attempt": user.failed_logins}
        if user.failed_logins >= s.login_max_attempts:
            user.locked_until = now + timedelta(minutes=s.login_lock_minutes)
            user.failed_logins = 0
            details["locked"] = True
        audit.record(db, "auth.login_failed", actor=user, ip=ip, details=details)
        db.commit()
        raise generic

    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = now
    audit.record(db, "auth.login", actor=user, ip=ip)
    db.commit()
    return _tokens(user)


@router.post("/refresh", response_model=TokenPair)
def refresh(body: RefreshIn, db: Session = Depends(get_db)) -> TokenPair:
    try:
        payload = decode_token(body.refresh_token, "refresh")
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    user = db.get(User, uuid.UUID(payload["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Compte inactif")
    revoke_token(payload)  # rotation: a refresh token is single-use
    return _tokens(user)


@router.post("/logout", status_code=204)
def logout(
    body: RefreshIn | None = None,
    ctx: Ctx = Depends(get_ctx),
    db: Session = Depends(get_db),
) -> None:
    revoke_token(ctx.token)
    if body and body.refresh_token:
        try:
            revoke_token(decode_token(body.refresh_token, "refresh"))
        except TokenError:
            pass
    audit.record(db, "auth.logout", actor=ctx.user, ip=ctx.ip)
    db.commit()


@router.get("/me", response_model=MeOut)
def me(ctx: Ctx = Depends(get_ctx)) -> MeOut:
    u = ctx.user
    return MeOut(id=u.id, email=u.email, full_name=u.full_name, role=u.role,
                 organization=OrgOut.model_validate(u.organization), permissions=permissions_for(u.role))


@router.post("/change-password", status_code=204)
def change_password(body: PasswordChangeIn, ctx: Ctx = Depends(get_ctx), db: Session = Depends(get_db)) -> None:
    if not verify_password(body.current_password, ctx.user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Mot de passe actuel incorrect")
    ctx.user.password_hash = hash_password(body.new_password)
    db.add(ctx.user)
    audit.record(db, "auth.password_changed", actor=ctx.user, ip=ctx.ip)
    db.commit()

