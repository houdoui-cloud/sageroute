import csv
import io
import json
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.core.rbac import Perm
from app.db import get_db
from app.deps import Ctx, require, scoped_get, scoped_query
from app.models import Incident, IntelItem, Ioc, IocType, Tlp, utcnow
from app.schemas import (
    IntelItemOut,
    IocCreate,
    IocImportIn,
    IocOut,
    IocUpdate,
    MatchIn,
    Page,
)
from app.services import audit
from app.services import ioc as svc

router = APIRouter(prefix="/intel", tags=["intelligence"])

FEED_FILE = Path(__file__).resolve().parent.parent / "data" / "osint_feed.json"


def to_out(ioc: Ioc, ctx: Ctx) -> IocOut:
    own = ioc.organization_id == ctx.org_id
    out = IocOut.model_validate(ioc)
    out.is_community = not own
    out.incident_refs = [i.reference for i in ioc.incidents] if own else []
    if not own:
        # Community view: never reveal who shared it or the original context.
        out.source = "communauté"
        out.description = ""
    return out


def upsert_ioc(db: Session, ctx: Ctx, ioc_type: IocType, value: str, *, tlp: str, confidence: int,
               source: str, description: str = "", tags: list[str] | None = None) -> tuple[Ioc, bool]:
    existing = db.scalar(scoped_query(Ioc, ctx).where(Ioc.type == ioc_type, Ioc.value == value))
    if existing:
        existing.sightings += 1
        existing.last_seen = utcnow()
        existing.confidence = max(existing.confidence, confidence)
        return existing, False
    ioc = Ioc(organization_id=ctx.org_id, type=ioc_type, value=value, tlp=tlp, confidence=confidence,
              source=source, description=description, tags=tags or [], created_by_id=ctx.user.id)
    db.add(ioc)
    db.flush()
    return ioc, True


@router.get("/iocs", response_model=Page[IocOut])
def list_iocs(
    type: IocType | None = None,
    tlp: Tlp | None = None,
    q: str | None = Query(default=None, max_length=200),
    include_community: bool = False,
    active_only: bool = True,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    ctx: Ctx = Depends(require(Perm.INTEL_READ)),
    db: Session = Depends(get_db),
) -> Page[IocOut]:
    scope = Ioc.organization_id == ctx.org_id
    if include_community:
        scope = or_(scope, and_(Ioc.shared.is_(True), Ioc.tlp == Tlp.CLEAR))
    stmt = select(Ioc).where(scope)
    if type:
        stmt = stmt.where(Ioc.type == type)
    if tlp:
        stmt = stmt.where(Ioc.tlp == tlp)
    if q:
        stmt = stmt.where(Ioc.value.ilike(f"%{q.lower()}%"))
    if active_only:
        stmt = stmt.where(Ioc.is_active.is_(True))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(Ioc.last_seen.desc()).offset((page - 1) * size).limit(size))
    return Page(items=[to_out(i, ctx) for i in rows], total=total, page=page, size=size)


@router.post("/iocs", response_model=IocOut, status_code=201)
def create_ioc(body: IocCreate, ctx: Ctx = Depends(require(Perm.INTEL_WRITE)),
               db: Session = Depends(get_db)) -> IocOut:
    try:
        ioc_type, value = svc.validate(body.value, body.type)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    ioc, created = upsert_ioc(db, ctx, ioc_type, value, tlp=body.tlp, confidence=body.confidence,
                              source=body.source, description=body.description, tags=body.tags)
    if body.incident_id:
        inc = scoped_get(db, Incident, body.incident_id, ctx)
        if inc not in ioc.incidents:
            ioc.incidents.append(inc)
    audit.record(db, "ioc.create" if created else "ioc.sighting", actor=ctx.user, organization_id=ctx.org_id,
                 target_type="ioc", target_id=ioc.id, ip=ctx.ip, details={"type": ioc_type, "value": value})
    db.commit()
    db.refresh(ioc)
    return to_out(ioc, ctx)


@router.get("/iocs/export")
def export_iocs(fmt: str = Query("csv", pattern="^(csv|json)$"), include_red: bool = False,
                ctx: Ctx = Depends(require(Perm.INTEL_READ)), db: Session = Depends(get_db)) -> StreamingResponse:
    stmt = scoped_query(Ioc, ctx).where(Ioc.is_active.is_(True))
    if not include_red:
        stmt = stmt.where(Ioc.tlp != Tlp.RED)
    rows = list(db.scalars(stmt.order_by(Ioc.type, Ioc.value)))
    audit.record(db, "ioc.export", actor=ctx.user, organization_id=ctx.org_id, ip=ctx.ip,
                 details={"format": fmt, "count": len(rows), "include_red": include_red})
    db.commit()
    if fmt == "json":
        data = [{"type": i.type, "value": i.value, "tlp": i.tlp, "confidence": i.confidence,
                 "first_seen": i.first_seen.isoformat(), "last_seen": i.last_seen.isoformat(), "tags": i.tags}
                for i in rows]
        return StreamingResponse(iter([json.dumps(data, ensure_ascii=False, indent=2)]), media_type="application/json",
                                 headers={"Content-Disposition": 'attachment; filename="iocs.json"'})
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "tlp", "confidence", "first_seen", "last_seen", "tags"])
    for i in rows:
        w.writerow([i.type, i.value, i.tlp, i.confidence, i.first_seen, i.last_seen, ";".join(i.tags)])
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="iocs.csv"'})


@router.patch("/iocs/{ioc_id}", response_model=IocOut)
def update_ioc(ioc_id: uuid.UUID, body: IocUpdate, ctx: Ctx = Depends(require(Perm.INTEL_WRITE)),
               db: Session = Depends(get_db)) -> IocOut:
    ioc = scoped_get(db, Ioc, ioc_id, ctx)
    changes = body.model_dump(exclude_unset=True)
    if ioc.shared and changes.get("tlp") not in (None, Tlp.CLEAR):
        # Narrowing a shared indicator would contradict what was already published.
        ioc.shared = False
    for key, value in changes.items():
        setattr(ioc, key, value)
    audit.record(db, "ioc.update", actor=ctx.user, organization_id=ctx.org_id, target_type="ioc",
                 target_id=ioc.id, ip=ctx.ip, details={"fields": list(changes)})
    db.commit()
    db.refresh(ioc)
    return to_out(ioc, ctx)


@router.get("/iocs/{ioc_id}/enrich")
def enrich(ioc_id: uuid.UUID, ctx: Ctx = Depends(require(Perm.INTEL_READ)), db: Session = Depends(get_db)) -> dict:
    ioc = scoped_get(db, Ioc, ioc_id, ctx)
    related = db.scalars(scoped_query(IntelItem, ctx)).all()
    bulletins = [{"id": str(b.id), "title": b.title} for b in related
                 if any(isinstance(x, dict) and x.get("value") == ioc.value for x in b.indicators)]
    return {**svc.enrich(ioc.type, ioc.value), "bulletins": bulletins,
            "incidents": [i.reference for i in ioc.incidents]}


@router.post("/iocs/{ioc_id}/link/{incident_id}", response_model=IocOut)
def link(ioc_id: uuid.UUID, incident_id: uuid.UUID, ctx: Ctx = Depends(require(Perm.INTEL_WRITE)),
         db: Session = Depends(get_db)) -> IocOut:
    ioc = scoped_get(db, Ioc, ioc_id, ctx)
    inc = scoped_get(db, Incident, incident_id, ctx)
    if inc not in ioc.incidents:
        ioc.incidents.append(inc)
        audit.record(db, "ioc.link", actor=ctx.user, organization_id=ctx.org_id, target_type="ioc",
                     target_id=ioc.id, ip=ctx.ip, details={"incident": inc.reference})
    db.commit()
    db.refresh(ioc)
    return to_out(ioc, ctx)


@router.delete("/iocs/{ioc_id}/link/{incident_id}", response_model=IocOut)
def unlink(ioc_id: uuid.UUID, incident_id: uuid.UUID, ctx: Ctx = Depends(require(Perm.INTEL_WRITE)),
           db: Session = Depends(get_db)) -> IocOut:
    ioc = scoped_get(db, Ioc, ioc_id, ctx)
    inc = scoped_get(db, Incident, incident_id, ctx)
    if inc in ioc.incidents:
        ioc.incidents.remove(inc)
        audit.record(db, "ioc.unlink", actor=ctx.user, organization_id=ctx.org_id, target_type="ioc",
                     target_id=ioc.id, ip=ctx.ip, details={"incident": inc.reference})
    db.commit()
    db.refresh(ioc)
    return to_out(ioc, ctx)


@router.post("/iocs/import")
def import_iocs(body: IocImportIn, ctx: Ctx = Depends(require(Perm.INTEL_WRITE)),
                db: Session = Depends(get_db)) -> dict:
    """Bulk import from free text, CSV lines or a defanged bulletin."""
    found = svc.extract(body.text)
    created = updated = 0
    for ioc_type, value in found[:5000]:
        _, is_new = upsert_ioc(db, ctx, ioc_type, value, tlp=body.tlp, confidence=body.confidence,
                               source=body.source)
        created += is_new
        updated += not is_new
    audit.record(db, "ioc.import", actor=ctx.user, organization_id=ctx.org_id, ip=ctx.ip,
                 details={"created": created, "updated": updated, "source": body.source})
    db.commit()
    return {"extracted": len(found), "created": created, "updated": updated}


@router.post("/match")
def match(body: MatchIn, ctx: Ctx = Depends(require(Perm.INTEL_READ)), db: Session = Depends(get_db)) -> dict:
    """Extract indicators from a text and say which ones are already known."""
    found = svc.extract(body.text)
    results = []
    for ioc_type, value in found[:1000]:
        known = db.scalars(select(Ioc).where(
            Ioc.type == ioc_type, Ioc.value == value,
            or_(Ioc.organization_id == ctx.org_id, and_(Ioc.shared.is_(True), Ioc.tlp == Tlp.CLEAR)),
        )).all()
        results.append({"type": ioc_type, "value": value,
                        "known": [to_out(k, ctx).model_dump(mode="json") for k in known]})
    return {"extracted": len(found), "matches": sum(1 for r in results if r["known"]), "indicators": results}


# --- OSINT feed (fictional, bundled offline) ------------------------------

@router.get("/feed", response_model=list[IntelItemOut])
def feed(tag: str | None = None, ctx: Ctx = Depends(require(Perm.INTEL_READ)),
         db: Session = Depends(get_db)) -> list[IntelItem]:
    items = db.scalars(scoped_query(IntelItem, ctx).order_by(IntelItem.published_at.desc()).limit(200)).all()
    return [i for i in items if not tag or tag in i.tags]


@router.post("/feed/sync")
def sync_feed(ctx: Ctx = Depends(require(Perm.INTEL_WRITE)), db: Session = Depends(get_db)) -> dict:
    """Load the bundled fictional OSINT bulletins and their indicators."""
    data = json.loads(FEED_FILE.read_text(encoding="utf-8"))
    added = 0
    for entry in data:
        exists = db.scalar(scoped_query(IntelItem, ctx).where(
            IntelItem.source == entry["source"], IntelItem.external_id == entry["id"]))
        if exists:
            continue
        db.add(IntelItem(organization_id=ctx.org_id, source=entry["source"], external_id=entry["id"],
                         title=entry["title"], summary=entry["summary"], severity=entry["severity"],
                         tags=entry["tags"], region=entry.get("region", "Afrique"),
                         indicators=entry["indicators"],
                         published_at=datetime.fromisoformat(entry["published_at"])))
        for ind in entry["indicators"]:
            try:
                t, v = svc.validate(ind["value"], IocType(ind["type"]))
            except ValueError:
                continue
            upsert_ioc(db, ctx, t, v, tlp=Tlp.GREEN, confidence=ind.get("confidence", 60),
                       source=entry["source"], description=entry["title"], tags=entry["tags"])
        added += 1
    audit.record(db, "intel.feed_sync", actor=ctx.user, organization_id=ctx.org_id, ip=ctx.ip,
                 details={"added": added})
    db.commit()
    return {"added": added, "total": len(data)}
