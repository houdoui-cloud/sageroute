from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AiSuggestion, DecisionRequest, Incident, IntakeReport, Ioc, aware, utcnow
from app.services.incidents import OPEN_STATUSES, is_sla_breached


def _mean_minutes(deltas: list[timedelta]) -> float | None:
    if not deltas:
        return None
    return round(sum(d.total_seconds() for d in deltas) / len(deltas) / 60, 1)


def compute(db: Session, org_id, start: datetime | None = None, end: datetime | None = None) -> dict:
    """Aggregate KPIs for an organisation. Computed in Python: V1 volumes are small
    and it keeps the logic identical on PostgreSQL and SQLite."""
    now = utcnow()
    end = end or now
    start = start or end - timedelta(days=30)

    incidents = db.scalars(select(Incident).where(Incident.organization_id == org_id)).unique().all()
    window = [i for i in incidents if start <= aware(i.created_at) <= end]
    open_ = [i for i in incidents if i.status in OPEN_STATUSES]

    ack = [aware(i.acknowledged_at) - aware(i.created_at) for i in window if i.acknowledged_at]
    res = [aware(i.resolved_at) - aware(i.created_at) for i in window if i.resolved_at]

    days = max(1, min((end - start).days, 366))
    trend = {(end - timedelta(days=d)).date().isoformat(): 0 for d in range(days - 1, -1, -1)}
    for i in window:
        key = aware(i.created_at).date().isoformat()
        if key in trend:
            trend[key] += 1

    reports = db.scalars(select(IntakeReport).where(IntakeReport.organization_id == org_id)).all()
    reports_window = [r for r in reports if start <= aware(r.created_at) <= end]

    return {
        "period": {"from": start.isoformat(), "to": end.isoformat()},
        "totals": {
            "incidents": len(window),
            "open": len(open_),
            "critical_open": sum(1 for i in open_ if i.severity == "critical"),
            "sla_breached_open": sum(1 for i in open_ if is_sla_breached(i, now)),
            "escalated_external": sum(1 for i in window if i.escalation_level == "external"),
            "reports_pending": sum(1 for r in reports if r.status == "received"),
            "iocs_active": len(db.scalars(select(Ioc.id).where(Ioc.organization_id == org_id,
                                                                Ioc.is_active.is_(True))).all()),
            "decisions_pending": len(db.scalars(select(DecisionRequest.id).where(
                DecisionRequest.organization_id == org_id, DecisionRequest.status == "pending")).all()),
            "ai_pending": len(db.scalars(select(AiSuggestion.id).where(
                AiSuggestion.organization_id == org_id, AiSuggestion.status == "proposed")).all()),
        },
        "mtta_minutes": _mean_minutes(ack),
        "mttr_minutes": _mean_minutes(res),
        "by_severity": dict(Counter(i.severity for i in window)),
        "by_status": dict(Counter(i.status for i in window)),
        "by_category": dict(Counter(i.category for i in window).most_common()),
        "open_by_severity": dict(Counter(i.severity for i in open_)),
        "reports_by_channel": dict(Counter(r.channel for r in reports_window)),
        "trend": [{"date": d, "count": c} for d, c in trend.items()],
        "sla_compliance_pct": (
            round(100 * sum(1 for i in window if not is_sla_breached(i, now)) / len(window), 1) if window else None
        ),
        "recent_critical": [
            {"id": str(i.id), "reference": i.reference, "title": i.title, "status": i.status,
             "created_at": aware(i.created_at).isoformat()}
            for i in sorted((i for i in open_ if i.severity in ("critical", "high")),
                            key=lambda i: aware(i.created_at), reverse=True)[:8]
        ],
    }
