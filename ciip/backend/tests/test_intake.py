from sqlalchemy import select

from app.models import AuditLog, IntakeReport
from app.seed import DEMO_INTAKE_TOKENS
from tests.conftest import ANALYST, LEAD, REPORTER, auth

API = "/api/v1"


def test_public_anonymous_report_and_tracking(client):
    resp = client.post(f"{API}/public/bfs/reports", json={
        "subject": "SMS frauduleux", "body": "Un SMS me demande mon code secret mobile money."})
    assert resp.status_code == 201
    code = resp.json()["tracking_code"]
    status = client.get(f"{API}/public/reports/{code}").json()
    assert status["status"] == "received"
    assert set(status) == {"tracking_code", "status", "label", "received_at"}  # nothing else leaks
    assert client.get(f"{API}/public/reports/SIG-NOPE0000").status_code == 404


def test_public_report_unknown_org(client):
    resp = client.post(f"{API}/public/inconnue/reports", json={"subject": "abc", "body": "x" * 20})
    assert resp.status_code == 404


def test_honeypot_stores_nothing(client, db):
    before = db.scalar(select(IntakeReport.id).order_by(IntakeReport.created_at.desc()).limit(1))
    resp = client.post(f"{API}/public/bfs/reports", json={
        "subject": "spam", "body": "spam spam spam spam", "website": "http://spam.example"})
    assert resp.status_code == 201
    after = db.scalar(select(IntakeReport.id).order_by(IntakeReport.created_at.desc()).limit(1))
    assert before == after


def test_public_rate_limit(client):
    body = {"subject": "Test limite", "body": "Corps de signalement suffisamment long"}
    codes = [client.post(f"{API}/public/bfs/reports", json=body).status_code for _ in range(21)]
    assert codes[-1] == 429


def test_webhook_requires_valid_token(client):
    url = f"{API}/intake/sms/bfs"
    body = {"sender": "+22500000042", "body": "Message suspect reçu avec un lien"}
    assert client.post(url, json=body).status_code == 401
    assert client.post(url, json=body, headers={"X-Intake-Token": "wrong"}).status_code == 401
    ok = client.post(url, json=body, headers={"X-Intake-Token": DEMO_INTAKE_TOKENS["bfs"]})
    assert ok.status_code == 201
    # The bfs token does not open the mdn inbox.
    assert client.post(f"{API}/intake/sms/mdn", json=body,
                       headers={"X-Intake-Token": DEMO_INTAKE_TOKENS["bfs"]}).status_code == 401
    assert client.post(f"{API}/intake/web/bfs", json=body,
                       headers={"X-Intake-Token": DEMO_INTAKE_TOKENS["bfs"]}).status_code == 404


def test_pii_encrypted_masked_and_reveal_audited(client, db):
    analyst = auth(client, ANALYST)
    client.post(f"{API}/reports", headers=analyst, json={
        "channel": "phone", "subject": "Appel client victime", "body": "Le client a perdu 50 000 FCFA via un faux agent.",
        "reporter": {"name": "Adjoa Mensah", "email": "adjoa.mensah@exemple.example", "phone": "+225 00 11 22 33"}})
    row = db.scalar(select(IntakeReport).where(IntakeReport.subject == "Appel client victime"))
    assert "adjoa" not in (row.reporter_email_enc or "")
    assert "Adjoa" not in (row.reporter_name_enc or "")

    masked = client.get(f"{API}/reports/{row.id}", headers=analyst).json()
    assert masked["pii_masked"] and masked["reporter_email"] == "a•••@exemple.example"
    assert masked["reporter_name"] == "A. M."
    assert client.get(f"{API}/reports/{row.id}", params={"reveal": True}, headers=analyst).status_code == 403

    lead = auth(client, LEAD)
    clear = client.get(f"{API}/reports/{row.id}", params={"reveal": True}, headers=lead).json()
    assert clear["reporter_email"] == "adjoa.mensah@exemple.example" and not clear["pii_masked"]
    db.expire_all()
    assert db.scalar(select(AuditLog).where(AuditLog.action == "pii.read", AuditLog.target_id == str(row.id)))


def test_convert_merge_and_reject(client):
    analyst = auth(client, ANALYST)
    receipts = [client.post(f"{API}/reports", headers=analyst, json={
        "channel": "email", "subject": f"Hameçonnage {i}", "body": "Faux site de la banque demandant les identifiants"}).json()
        for i in range(3)]
    reports = {r["tracking_code"]: r for r in client.get(f"{API}/reports", params={"size": 200}, headers=analyst).json()["items"]}
    r1, r2, r3 = (reports[x["tracking_code"]] for x in receipts)
    assert r1["category_hint"] == "phishing"

    inc = client.post(f"{API}/reports/{r1['id']}/convert", json={"severity": "high"}, headers=analyst).json()
    assert inc["category"] == "phishing" and inc["source_channel"] == "email" and inc["severity"] == "high"
    assert client.post(f"{API}/reports/{r1['id']}/convert", json={}, headers=analyst).status_code == 409

    merged = client.post(f"{API}/reports/{r2['id']}/convert", json={"merge_into_incident_id": inc["id"]},
                         headers=analyst).json()
    assert merged["id"] == inc["id"]
    assert sum(1 for e in merged["events"] if e["kind"] == "report_merged") == 2

    rej = client.post(f"{API}/reports/{r3['id']}/reject", json={"reason": "Doublon"}, headers=analyst).json()
    assert rej["status"] == "rejected"
    assert client.get(f"{API}/public/reports/{r3['tracking_code']}").json()["status"] == "rejected"


def test_reporter_sees_only_own_reports(client):
    reporter = auth(client, REPORTER)
    assert client.post(f"{API}/reports", headers=reporter, json={
        "channel": "sms", "subject": "Canal interdit", "body": "Le déclarant ne choisit pas le canal"}).status_code == 403
    assert client.post(f"{API}/reports", headers=reporter, json={
        "subject": "Poste bloqué en agence", "body": "Message de rançon affiché sur le poste du guichet"}).status_code == 201
    mine = client.get(f"{API}/reports", headers=reporter).json()
    assert mine["total"] == 1 and mine["items"][0]["subject"] == "Poste bloqué en agence"
    assert mine["items"][0]["category_hint"] == "ransomware"
