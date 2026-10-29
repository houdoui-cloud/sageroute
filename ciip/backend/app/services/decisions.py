"""Four-eyes workflow: sensitive actions run only once a second, cleared person approves."""

from collections.abc import Callable
from datetime import timedelta

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.privacy import redact
from app.models import (
    DecisionRequest,
    Escalation,
    EscalationLevel,
    Incident,
    IncidentStatus,
    IntakeReport,
    Ioc,
    Organization,
    Severity,
    Tlp,
    utcnow,
)
from app.services import incidents as inc_svc

# type → (target table, human label)
DECISION_TYPES: dict[str, tuple[str, str]] = {
    "close_critical_incident": ("incident", "Clôture d'un incident critique"),
    "external_escalation": ("incident", "Escalade vers le CERT national"),
    "share_ioc": ("ioc", "Partage communautaire d'un indicateur"),
    "purge_data": ("organization", "Purge des données au-delà de la rétention"),
}


def load_target(db: Session, decision_type: str, target_id, org_id):
    target_type, _ = DECISION_TYPES[decision_type]
    if target_type == "organization":
        return db.get(Organization, org_id)
    model = {"incident": Incident, "ioc": Ioc}[target_type]
    obj = db.get(model, target_id) if target_id else None
    if obj is None or obj.organization_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Cible introuvable")
    return obj


def precheck(db: Session, decision_type: str, target) -> None:
    """Reject requests that could never be executed, before anyone reviews them."""
    if decision_type == "close_critical_incident":
        if target.severity != Severity.CRITICAL:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "L'incident n'est pas critique : clôture directe possible")
        inc_svc.check_transition(target.status, IncidentStatus.CLOSED)
    elif decision_type == "external_escalation":
        if target.escalation_level == EscalationLevel.EXTERNAL:
            raise HTTPException(status.HTTP_409_CONFLICT, "Incident déjà escaladé à l'externe")
    elif decision_type == "share_ioc":
        if target.shared:
            raise HTTPException(status.HTTP_409_CONFLICT, "Indicateur déjà partagé")
        if target.tlp == Tlp.RED:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Un indicateur TLP:RED ne peut pas être partagé")


def _close_critical(db: Session, d: DecisionRequest, target: Incident, approver) -> dict:
    inc_svc.check_transition(target.status, IncidentStatus.CLOSED)
    old = target.status
    inc_svc.apply_status(target, IncidentStatus.CLOSED)
    inc_svc.add_event(db, target, approver, "status_change",
                      f"Clôture approuvée (décision {d.id})", **{"from": old, "to": IncidentStatus.CLOSED})
    return {"status": target.status}


def _external(db: Session, d: DecisionRequest, target: Incident, approver) -> dict:
    db.add(Escalation(incident_id=target.id, organization_id=target.organization_id,
                      from_level=target.escalation_level, to_level=EscalationLevel.EXTERNAL,
                      reason=d.justification, escalated_by_id=d.requested_by_id))
    old = target.escalation_level
    target.escalation_level = EscalationLevel.EXTERNAL
    # Demo only: the transmission to the (fictional) national CERT is simulated.
    ticket = f"CERT-DEMO-{utcnow():%Y%m%d}-{str(target.id)[:6].upper()}"
    inc_svc.add_event(db, target, approver, "escalation",
                      f"Escalade externe approuvée — transmis au CERT national (simulé), réf. {ticket}",
                      **{"from": old, "to": EscalationLevel.EXTERNAL, "external_ref": ticket})
    return {"external_ref": ticket}


def _share(db: Session, d: DecisionRequest, target: Ioc, approver) -> dict:
    target.shared = True
    target.tlp = Tlp.CLEAR
    return {"shared": True, "tlp": target.tlp}


def _purge(db: Session, d: DecisionRequest, org: Organization, approver) -> dict:
    cutoff = utcnow() - timedelta(days=org.retention_days)
    reports = db.scalars(select(IntakeReport).where(
        IntakeReport.organization_id == org.id, IntakeReport.created_at < cutoff,
        IntakeReport.status != "received")).all()
    for r in reports:
        r.reporter_name_enc = r.reporter_email_enc = r.reporter_phone_enc = None
        r.body = "[contenu purgé — durée de rétention dépassée]"
    incidents = db.scalars(select(Incident).where(
        Incident.organization_id == org.id, Incident.closed_at.is_not(None), Incident.closed_at < cutoff)).all()
    for i in incidents:
        i.description = redact(i.description)
    return {"reports_purged": len(reports), "incidents_redacted": len(incidents), "cutoff": cutoff.isoformat()}


EXECUTORS: dict[str, Callable] = {
    "close_critical_incident": _close_critical,
    "external_escalation": _external,
    "share_ioc": _share,
    "purge_data": _purge,
}


def execute(db: Session, d: DecisionRequest, approver) -> dict:
    target = load_target(db, d.type, d.target_id, d.organization_id)
    return EXECUTORS[d.type](db, d, target, approver)
