import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.core.kv import get_kv
from app.core.labels import CATEGORY_FR, CHANNEL_FR, SEVERITY_FR, STATUS_FR, fr
from app.core.rbac import Perm
from app.db import get_db
from app.deps import Ctx, require
from app.models import aware
from app.services import audit, stats

router = APIRouter(tags=["statistiques et rapports"])

@router.get("/analytics/dashboard")
def dashboard(ctx: Ctx = Depends(require(Perm.DASHBOARD_READ)), db: Session = Depends(get_db)) -> dict:
    key = f"stats:{ctx.org_id}:dashboard"
    kv = get_kv()
    cached = kv.get(key)
    if cached:
        return json.loads(cached)
    data = stats.compute(db, ctx.org_id)
    kv.set(key, json.dumps(data), 30)
    return data


def _period(date_from: datetime | None, date_to: datetime | None) -> tuple[datetime | None, datetime | None]:
    start, end = aware(date_from), aware(date_to)
    if start and end and start > end:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Période invalide")
    return start, end


@router.get("/analytics/summary")
def summary(date_from: datetime | None = None, date_to: datetime | None = None,
            ctx: Ctx = Depends(require(Perm.REPORTS_READ)), db: Session = Depends(get_db)) -> dict:
    start, end = _period(date_from, date_to)
    return stats.compute(db, ctx.org_id, start, end)


def _fmt_minutes(value: float | None) -> str:
    if value is None:
        return "n/d"
    if value < 120:
        return f"{value:.0f} min"
    if value < 60 * 48:
        return f"{value / 60:.1f} h"
    return f"{value / 1440:.1f} j"


@router.get("/analytics/executive", response_class=PlainTextResponse)
def executive(date_from: datetime | None = None, date_to: datetime | None = None,
              ctx: Ctx = Depends(require(Perm.REPORTS_READ)), db: Session = Depends(get_db)) -> str:
    """Management-level report in Markdown (easy to paste or convert to PDF)."""
    start, end = _period(date_from, date_to)
    s = stats.compute(db, ctx.org_id, start, end)
    t = s["totals"]
    org = ctx.user.organization if ctx.org_id == ctx.user.organization_id else None
    lines = [
        f"# Rapport exécutif cybersécurité — {org.name if org else ctx.org_id}",
        "",
        f"Période : {s['period']['from'][:10]} → {s['period']['to'][:10]}  ",
        "Classification : **TLP:AMBER** — diffusion restreinte à la direction.  ",
        "_Démonstrateur : données entièrement fictives._",
        "",
        "## Synthèse",
        f"- Incidents déclarés sur la période : **{t['incidents']}**",
        f"- Incidents ouverts : **{t['open']}** dont **{t['critical_open']}** critiques",
        f"- Incidents ouverts hors SLA : **{t['sla_breached_open']}**",
        f"- Taux de respect des SLA : **{s['sla_compliance_pct'] if s['sla_compliance_pct'] is not None else 'n/d'} %**",
        f"- Délai moyen de prise en charge (MTTA) : **{_fmt_minutes(s['mtta_minutes'])}**",
        f"- Délai moyen de résolution (MTTR) : **{_fmt_minutes(s['mttr_minutes'])}**",
        f"- Escalades au CERT national : **{t['escalated_external']}**",
        f"- Signalements en attente de tri : **{t['reports_pending']}**",
        "",
        "## Répartition par sévérité",
        *[f"- {fr(SEVERITY_FR, k).capitalize()} : {v}" for k, v in s["by_severity"].items()],
        "",
        "## Principales menaces (catégories)",
        *[f"{n}. {fr(CATEGORY_FR, k)} — {v}" for n, (k, v) in enumerate(s["by_category"].items(), 1)],
        "",
        "## Canaux de signalement",
        *[f"- {fr(CHANNEL_FR, k)} : {v}" for k, v in s["reports_by_channel"].items()],
        "",
        "## Incidents majeurs en cours",
        *([f"- {i['reference']} — {i['title']} ({fr(STATUS_FR, i['status'])})" for i in s["recent_critical"]] or ["- Aucun"]),
        "",
        "## Points d'attention",
        f"- Décisions sensibles en attente d'approbation : {t['decisions_pending']}",
        f"- Suggestions IA en attente de validation : {t['ai_pending']}",
        "",
        "_Rapport généré automatiquement ; les chiffres doivent être revus par le RSSI avant diffusion._",
    ]
    audit.record(db, "report.executive", actor=ctx.user, organization_id=ctx.org_id, ip=ctx.ip)
    db.commit()
    return "\n".join(lines)
