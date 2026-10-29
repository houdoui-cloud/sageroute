"""Load a fully fictional demo dataset. Idempotent: does nothing if already seeded.

    python -m app.seed
"""

import json
import random
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.intake import hash_intake_token, tracking_code
from app.api.intel import FEED_FILE
from app.core.privacy import encrypt
from app.core.rbac import Role
from app.core.security import hash_password
from app.db import SessionLocal
from app.models import (
    Category,
    Channel,
    EscalationLevel,
    Incident,
    IntakeReport,
    IntelItem,
    Ioc,
    Organization,
    Playbook,
    Severity,
    Tlp,
    User,
    utcnow,
)
from app.models import (
    IncidentStatus as S,
)
from app.services import audit
from app.services import incidents as inc_svc
from app.services import ioc as ioc_svc
from app.services.playbook_library import REFERENCE_PLAYBOOKS

DEMO_PASSWORD = "DemoCiip2026!"
DEMO_INTAKE_TOKENS = {"bfs": "demo-intake-token-bfs", "mdn": "demo-intake-token-mdn"}

ORGS = [
    ("CIIP — Opérateur de la plateforme", "plateforme", "plateforme", "—"),
    ("Banque Fictive du Sahel", "bfs", "finance", "République de Kalanda (fictive)"),
    ("Ministère Démo du Numérique", "mdn", "secteur public", "République de Kalanda (fictive)"),
]

USERS = [
    ("plateforme", "superadmin@ciip.example", "Awa Opératrice", Role.SUPER_ADMIN),
    ("bfs", "admin@bfs.example", "Moussa Administrateur", Role.ORG_ADMIN),
    ("bfs", "lead@bfs.example", "Aminata Analyste-Principale", Role.LEAD_ANALYST),
    ("bfs", "analyste@bfs.example", "Kofi Analyste", Role.ANALYST),
    ("bfs", "analyste2@bfs.example", "Fatou Analyste", Role.ANALYST),
    ("bfs", "declarant@bfs.example", "Ibrahim Agent-Agence", Role.REPORTER),
    ("bfs", "auditeur@bfs.example", "Ngozi Auditrice", Role.AUDITOR),
    ("mdn", "admin@mdn.example", "Chinedu Administrateur", Role.ORG_ADMIN),
    ("mdn", "lead@mdn.example", "Zainab Analyste-Principale", Role.LEAD_ANALYST),
    ("mdn", "analyste@mdn.example", "Thabo Analyste", Role.ANALYST),
]

INCIDENT_TEMPLATES = [
    (Category.PHISHING, "Campagne d'hameçonnage usurpant la banque en ligne",
     "Plusieurs clients signalent un courriel les invitant à se connecter sur bfs-secure-login.example. "
     "Le lien pointe vers 198.51.100.23."),
    (Category.MOBILE_MONEY_FRAUD, "Transferts mobile money frauduleux après SIM swap",
     "Un client signale des transferts non autorisés vers +22500000001 après la perte de réseau de sa SIM."),
    (Category.RANSOMWARE, "Serveurs de fichiers chiffrés en agence",
     "Fichiers renommés en .kalalock sur le serveur de l'agence de Kalanda-Nord. Note de rançon présente. "
     "Connexions VPN suspectes depuis 203.0.113.45."),
    (Category.DDOS, "Indisponibilité du portail de services en ligne",
     "Trafic massif sur le portail citoyen depuis 192.0.2.77 et 192.0.2.78, service saturé."),
    (Category.DATA_BREACH, "Fichier de clients exposé sur un partage public",
     "Un export contenant des données personnelles de clients a été trouvé sur un partage accessible publiquement."),
    (Category.ACCOUNT_COMPROMISE, "Compte de messagerie d'un directeur compromis",
     "Connexion inhabituelle et règle de transfert automatique créée vers une adresse externe."),
    (Category.MALWARE, "Poste infecté après ouverture d'une pièce jointe",
     "L'antivirus a détecté un cheval de troie (empreinte 44d88612fea8a8f36de82e1278abb02f)."),
    (Category.UNAUTHORIZED_ACCESS, "Tentatives de force brute sur le RDP exposé",
     "Des milliers de tentatives d'authentification depuis 203.0.113.46 sur un serveur RDP."),
    (Category.DEFACEMENT, "Page d'accueil du site institutionnel modifiée",
     "La page d'accueil affiche « hacked by » et un message revendicatif."),
    (Category.SOCIAL_ENGINEERING, "Faux appel du directeur général demandant un virement urgent",
     "Un collaborateur de la comptabilité a reçu un appel se faisant passer pour le DG (fraude au président)."),
]

REPORT_SAMPLES = [
    (Channel.PUBLIC_FORM, "SMS suspect reçu", "J'ai reçu un SMS me demandant de confirmer mon compte mobile money sur momo-verification.example."),
    (Channel.EMAIL, "Courriel étrange de la banque", "Un message me demande mon mot de passe pour « mise à jour de sécurité »."),
    (Channel.WHATSAPP, "Faux agent sur WhatsApp", "Une personne se présentant comme agent de la banque demande mon code de retrait."),
    (Channel.SMS, "Lien suspect", "Lien reçu par SMS : hxxp://momo-verification[.]example/compte/confirmer"),
    (Channel.PHONE, "Appel d'un client : carte débitée", "Le client signale des débits inconnus sur sa carte après un achat en ligne."),
    (Channel.WEB, "Poste lent et fenêtres publicitaires", "Depuis hier mon poste affiche des fenêtres et l'antivirus est désactivé."),
]


def _seed_playbooks(db: Session) -> None:
    if db.scalar(select(Playbook).where(Playbook.organization_id.is_(None))):
        return
    for cat, pb in REFERENCE_PLAYBOOKS.items():
        db.add(Playbook(organization_id=None, name=pb["name"], category=cat, description=pb["description"],
                        steps=pb["steps"], status="active"))


def _seed_incidents(db: Session, org: Organization, users: list[User], count: int, rng: random.Random) -> None:
    analysts = [u for u in users if u.role in (Role.ANALYST, Role.LEAD_ANALYST)]
    now = utcnow()
    playbooks = {p.category: p.id for p in db.scalars(select(Playbook).where(Playbook.organization_id.is_(None)))}
    for n in range(count):
        cat, title, desc = INCIDENT_TEMPLATES[n % len(INCIDENT_TEMPLATES)]
        created = now - timedelta(days=rng.uniform(0, 29), hours=rng.uniform(0, 23))
        severity = rng.choices(list(Severity), weights=[1, 3, 4, 2])[0]
        if cat == Category.RANSOMWARE:
            severity = Severity.CRITICAL
        age_days = (now - created).days
        if age_days < 3:
            status = rng.choice([S.NEW, S.TRIAGED, S.IN_PROGRESS])
        elif age_days < 8:
            status = rng.choice([S.IN_PROGRESS, S.CONTAINED, S.RESOLVED])
        else:
            status = rng.choice([S.RESOLVED, S.CLOSED, S.CLOSED, S.CLOSED, S.REJECTED])
        inc = Incident(
            organization_id=org.id,
            reference=inc_svc.next_reference(db, org.id, created),
            title=title if n < len(INCIDENT_TEMPLATES) else f"{title} (#{n + 1})",
            description=desc,
            category=cat,
            severity=severity,
            status=status,
            source_channel=rng.choice(list(Channel)),
            escalation_level=rng.choice([EscalationLevel.L1, EscalationLevel.L1, EscalationLevel.L2, EscalationLevel.L3]),
            affected_assets=rng.sample(["core-banking", "portail-web", "messagerie", "agence-nord", "vpn", "poste-compta"], 2),
            tags=[cat.value],
            playbook_id=playbooks.get(cat) if status != S.NEW else None,
            assignee_id=rng.choice(analysts).id if status != S.NEW else None,
            created_at=created,
            updated_at=created,
        )
        inc_svc.apply_sla(inc, created)
        ack_d, res_d = inc_svc.SLA[severity]
        if status != S.NEW:
            inc.acknowledged_at = created + ack_d * rng.uniform(0.2, 1.3)
        if status in (S.RESOLVED, S.CLOSED):
            inc.resolved_at = min(now, created + res_d * rng.uniform(0.3, 1.2))
        if status == S.CLOSED:
            inc.closed_at = inc.resolved_at
        db.add(inc)
        db.flush()
        inc_svc.add_event(db, inc, None, "created", "Incident créé (données de démonstration)").created_at = created
        if inc.assignee_id:
            inc_svc.add_event(db, inc, None, "assignment", "Assignation initiale").created_at = inc.acknowledged_at
        for t, v in ioc_svc.extract(desc):
            ioc = db.scalar(select(Ioc).where(Ioc.organization_id == org.id, Ioc.type == t, Ioc.value == v))
            if ioc is None:
                ioc = Ioc(organization_id=org.id, type=t, value=v, tlp=Tlp.AMBER, confidence=60,
                          source="incident", first_seen=created, last_seen=created)
                db.add(ioc)
                db.flush()
            if inc not in ioc.incidents:
                ioc.incidents.append(inc)


def _seed_reports(db: Session, org: Organization, rng: random.Random) -> None:
    now = utcnow()
    for channel, subject, body in REPORT_SAMPLES:
        anonymous = channel == Channel.PUBLIC_FORM
        db.add(IntakeReport(
            organization_id=org.id, tracking_code=tracking_code(), channel=channel, subject=subject, body=body,
            category_hint=None, is_anonymous=anonymous,
            reporter_name_enc=None if anonymous else encrypt("Client Fictif"),
            reporter_email_enc=None if anonymous else encrypt("client.fictif@exemple.example"),
            reporter_phone_enc=None if anonymous else encrypt("+225 00 00 00 99"),
            created_at=now - timedelta(hours=rng.uniform(1, 72)),
        ))


def _seed_feed(db: Session, org: Organization) -> None:
    for entry in json.loads(FEED_FILE.read_text(encoding="utf-8")):
        db.add(IntelItem(organization_id=org.id, source=entry["source"], external_id=entry["id"],
                         title=entry["title"], summary=entry["summary"], severity=entry["severity"],
                         tags=entry["tags"], region=entry.get("region", "Afrique"), indicators=entry["indicators"],
                         published_at=datetime.fromisoformat(entry["published_at"])))
        for ind in entry["indicators"]:
            t, v = ioc_svc.validate(ind["value"], None)
            if not db.scalar(select(Ioc).where(Ioc.organization_id == org.id, Ioc.type == t, Ioc.value == v)):
                db.add(Ioc(organization_id=org.id, type=t, value=v, tlp=Tlp.GREEN, confidence=ind.get("confidence", 60),
                           source=entry["source"], description=entry["title"], tags=entry["tags"]))
        db.flush()


def seed(db: Session) -> bool:
    if db.scalar(select(Organization).where(Organization.slug == "bfs")):
        return False
    rng = random.Random(2026)
    _seed_playbooks(db)
    orgs: dict[str, Organization] = {}
    for name, slug, sector, country in ORGS:
        org = Organization(name=name, slug=slug, sector=sector, country=country)
        if slug in DEMO_INTAKE_TOKENS:
            org.intake_token_hash = hash_intake_token(DEMO_INTAKE_TOKENS[slug])
        db.add(org)
        orgs[slug] = org
    db.flush()
    pwd = hash_password(DEMO_PASSWORD)
    users: dict[str, list[User]] = {}
    for slug, email, name, role in USERS:
        u = User(organization_id=orgs[slug].id, email=email, full_name=name, role=role, password_hash=pwd)
        db.add(u)
        users.setdefault(slug, []).append(u)
    db.flush()
    _seed_incidents(db, orgs["bfs"], users["bfs"], 28, rng)
    _seed_incidents(db, orgs["mdn"], users["mdn"], 10, rng)
    _seed_reports(db, orgs["bfs"], rng)
    _seed_reports(db, orgs["mdn"], rng)
    _seed_feed(db, orgs["bfs"])
    _seed_feed(db, orgs["mdn"])
    audit.record(db, "seed.demo", details={"orgs": list(orgs), "note": "données fictives"})
    db.commit()
    return True


def main() -> None:
    with SessionLocal() as db:
        if seed(db):
            print("Jeu de données fictif chargé.")
            print(f"Comptes de démonstration (mot de passe : {DEMO_PASSWORD}) :")
            for _, email, _, role in USERS:
                print(f"  {email:<28} {role}")
        else:
            print("Données déjà présentes, rien à faire.")


if __name__ == "__main__":
    main()
