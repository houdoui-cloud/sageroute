import hashlib
import json
import uuid
from datetime import datetime

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models import AuditLog, aware, utcnow

GENESIS = "0" * 64


def _canonical(entry: AuditLog) -> str:
    created = aware(entry.created_at)
    return json.dumps(
        {
            "org": str(entry.organization_id) if entry.organization_id else None,
            "actor": str(entry.actor_id) if entry.actor_id else None,
            "email": entry.actor_email,
            "action": entry.action,
            "target_type": entry.target_type,
            "target_id": entry.target_id,
            "ip": entry.ip,
            "details": entry.details,
            "at": created.isoformat() if isinstance(created, datetime) else None,
        },
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )


def compute_hash(prev_hash: str, entry: AuditLog) -> str:
    return hashlib.sha256((prev_hash + _canonical(entry)).encode()).hexdigest()


def record(
    db: Session,
    action: str,
    *,
    actor=None,
    organization_id: uuid.UUID | None = None,
    target_type: str | None = None,
    target_id: object = None,
    ip: str | None = None,
    details: dict | None = None,
) -> AuditLog:
    """Append an audit entry to the chain. The caller commits."""
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        # Serialise writers so the chain never forks.
        db.execute(text("SELECT pg_advisory_xact_lock(7314159)"))
    db.flush()
    last = db.scalar(select(AuditLog.hash).order_by(AuditLog.id.desc()).limit(1))
    prev = last or GENESIS
    entry = AuditLog(
        organization_id=organization_id or (actor.organization_id if actor else None),
        actor_id=actor.id if actor else None,
        actor_email=actor.email if actor else None,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        ip=ip,
        details=json.loads(json.dumps(details or {}, default=str)),
        created_at=utcnow().replace(microsecond=0),
        prev_hash=prev,
    )
    entry.hash = compute_hash(prev, entry)
    db.add(entry)
    db.flush()
    return entry


def verify_chain(db: Session) -> dict:
    prev = GENESIS
    count = 0
    for entry in db.scalars(select(AuditLog).order_by(AuditLog.id)):
        count += 1
        if entry.prev_hash != prev or compute_hash(prev, entry) != entry.hash:
            return {"valid": False, "checked": count, "broken_at_id": entry.id}
        prev = entry.hash
    return {"valid": True, "checked": count, "broken_at_id": None}
