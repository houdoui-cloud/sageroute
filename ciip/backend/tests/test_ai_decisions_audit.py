import json

import httpx
from sqlalchemy import select, update

from app.core import config
from app.core.privacy import decrypt, encrypt, mask_phone, redact
from app.models import AuditLog
from app.services import ai, audit
from tests.conftest import ADMIN, ANALYST, ANALYST2, AUDITOR, LEAD, auth, new_incident

API = "/api/v1"


# --- Privacy --------------------------------------------------------------

def test_redaction_keeps_indicators():
    text = "Contact a.b@x.example ou +221 77 000 00 00, carte 4111 1111 1111 1111, IP 192.0.2.10, hash 44d88612fea8a8f36de82e1278abb02f"
    out = redact(text)
    assert "a.b@x.example" not in out and "4111" not in out and "77 000" not in out
    assert "192.0.2.10" in out and "44d88612fea8a8f36de82e1278abb02f" in out


def test_encryption_roundtrip():
    token = encrypt("Secret Fictif")
    assert token and "Secret" not in token
    assert decrypt(token) == "Secret Fictif"
    assert mask_phone("+225 00 00 00 99") == "•••99"


# --- AI -------------------------------------------------------------------

def test_rules_triage_categories():
    assert ai.rules_triage("Tous nos fichiers sont chiffrés, rançon en bitcoin")["category"] == "ransomware"
    assert ai.rules_triage("Transfert frauduleux sur mon compte orange money après sim swap")["category"] == "mobile_money_fraud"
    r = ai.rules_triage("Rançongiciel sur les serveurs de production et les sauvegardes, propagation en cours")
    assert r["severity"] == "critical"
    assert ai.rules_triage("Bonjour")["category"] == "other"


def test_triage_suggestion_needs_lead_validation(client):
    analyst, lead = auth(client, ANALYST), auth(client, LEAD)
    inc = new_incident(client, analyst, title="Serveurs chiffrés",
                       description="Rançon demandée en bitcoin, fichiers chiffrés .lock. Contact: x@y.example",
                       category="other", severity="low")
    sug = client.post(f"{API}/ai/triage", json={"incident_id": inc["id"]}, headers=analyst).json()
    assert sug["status"] == "proposed" and sug["engine"] == "rules"
    assert "x@y.example" not in sug["prompt_redacted"]
    assert "validée par un analyste habilité" in sug["output"]["disclaimer"]
    # Nothing changes before validation.
    assert client.get(f"{API}/incidents/{inc['id']}", headers=analyst).json()["severity"] == "low"

    r = client.post(f"{API}/ai/suggestions/{sug['id']}/review", json={"approve": True, "comment": "Cohérent"},
                    headers=lead).json()
    assert r["status"] == "validated"
    detail = client.get(f"{API}/incidents/{inc['id']}", headers=analyst).json()
    assert detail["category"] == "ransomware" and detail["severity"] == "critical"
    assert detail["playbook_id"] is not None
    assert any(e["kind"] == "ai_validated" for e in detail["events"])
    again = client.post(f"{API}/ai/suggestions/{sug['id']}/review", json={"approve": True}, headers=lead)
    assert again.status_code == 409


def test_free_text_triage_is_informational(client):
    sug = client.post(f"{API}/ai/triage", json={"text": "DDoS massif sur le portail"}, headers=auth(client, ANALYST)).json()
    assert sug["status"] == "informational" and sug["output"]["category"] == "ddos"


def test_playbook_generation_validated_becomes_org_playbook(client):
    analyst, lead = auth(client, ANALYST), auth(client, LEAD)
    sug = client.post(f"{API}/ai/playbook", json={"category": "phishing", "context": "Agences rurales"},
                      headers=analyst).json()
    assert sug["output"]["steps"]
    client.post(f"{API}/ai/suggestions/{sug['id']}/review", json={"approve": True}, headers=lead)
    names = [p["name"] for p in client.get(f"{API}/playbooks", params={"category": "phishing"}, headers=analyst).json()]
    assert any("(adapté)" in n for n in names)


def test_ask_answers_with_rules_engine(client):
    r = client.post(f"{API}/ai/ask", headers=auth(client, ANALYST),
                    json={"question": "Faut-il notifier le régulateur pour cette fuite de données personnelles ?"}).json()
    assert "décision sensible" in r["output"]["answer"]


def test_ollama_output_is_validated(monkeypatch):
    monkeypatch.setattr(config.get_settings(), "ai_use_ollama", True)

    def fake_post(url, json, timeout):  # noqa: A002
        body = {"category": "phishing", "severity": "high", "summary": "Hameçonnage",
                "rationale": ["lien"], "next_steps": ["bloquer"], "confidence": 0.8}
        return httpx.Response(200, json={"response": __import__("json").dumps(body)}, request=httpx.Request("POST", url))

    monkeypatch.setattr(ai.httpx, "post", fake_post)
    r = ai.triage("Lien suspect reçu")
    assert r.engine.startswith("ollama:") and r.output["severity"] == "high"
    assert r.output["rules_engine_opinion"]["category"]

    def bad_post(url, json, timeout):  # noqa: A002
        return httpx.Response(200, json={"response": '{"category": "pirates", "severity": "apocalypse"}'},
                              request=httpx.Request("POST", url))

    monkeypatch.setattr(ai.httpx, "post", bad_post)
    assert ai.triage("Fichiers chiffrés, rançon").engine == "rules"

    def down(url, json, timeout):  # noqa: A002
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(ai.httpx, "post", down)
    assert ai.triage("Fichiers chiffrés, rançon").output["category"] == "ransomware"


# --- Decisions ------------------------------------------------------------

def test_four_eyes(client):
    lead = auth(client, LEAD)
    inc = new_incident(client, lead, severity="high")
    d = client.post(f"{API}/decisions", headers=lead, json={
        "type": "external_escalation", "target_id": inc["id"], "justification": "Demande par le lead lui-même"}).json()
    assert client.post(f"{API}/decisions/{d['id']}/review", json={"approve": True}, headers=lead).status_code == 403
    analyst = auth(client, ANALYST)
    assert client.post(f"{API}/decisions/{d['id']}/review", json={"approve": True}, headers=analyst).status_code == 403
    admin = auth(client, ADMIN)
    r = client.post(f"{API}/decisions/{d['id']}/review", json={"approve": False, "comment": "Pas nécessaire"},
                    headers=admin).json()
    assert r["status"] == "rejected"
    assert client.get(f"{API}/incidents/{inc['id']}", headers=lead).json()["escalation_level"] == "L1"


def test_decision_validation(client):
    analyst = auth(client, ANALYST2)
    inc = new_incident(client, analyst, severity="medium")
    body = {"type": "close_critical_incident", "target_id": inc["id"], "justification": "Clôture demandée"}
    assert client.post(f"{API}/decisions", json=body, headers=analyst).status_code == 400  # not critical
    assert client.post(f"{API}/decisions", headers=analyst,
                       json={**body, "type": "nuke_everything"}).status_code == 400
    ext = {"type": "external_escalation", "target_id": inc["id"], "justification": "Raison suffisante"}
    assert client.post(f"{API}/decisions", json=ext, headers=analyst).status_code == 201
    assert client.post(f"{API}/decisions", json=ext, headers=analyst).status_code == 409
    purge = {"type": "purge_data", "justification": "Application de la politique de rétention"}
    assert client.post(f"{API}/decisions", json=purge, headers=analyst).status_code == 403


def test_purge_decision(client):
    admin, lead = auth(client, ADMIN), auth(client, LEAD)
    d = client.post(f"{API}/decisions", headers=admin,
                    json={"type": "purge_data", "justification": "Application de la politique de rétention"}).json()
    r = client.post(f"{API}/decisions/{d['id']}/review", json={"approve": True}, headers=lead)
    assert r.status_code == 200 and r.json()["status"] == "approved"


# --- Audit, stats, reports ------------------------------------------------

def test_audit_chain_detects_tampering(client, db):
    headers = auth(client, AUDITOR)
    assert client.get(f"{API}/admin/audit/verify", headers=headers).json()["valid"] is True
    entry = db.scalar(select(AuditLog).order_by(AuditLog.id).offset(3).limit(1))
    original = entry.details
    db.execute(update(AuditLog).where(AuditLog.id == entry.id).values(details={"forged": True}))
    db.commit()
    result = client.get(f"{API}/admin/audit/verify", headers=headers).json()
    assert result["valid"] is False and result["broken_at_id"] == entry.id
    db.execute(update(AuditLog).where(AuditLog.id == entry.id).values(details=original))
    db.commit()
    assert audit.verify_chain(db)["valid"] is True


def test_audit_log_is_org_scoped(client):
    logs = client.get(f"{API}/admin/audit", params={"size": 500}, headers=auth(client, AUDITOR)).json()["items"]
    assert logs and all(e["actor_email"] is None or e["actor_email"].endswith(("@bfs.example",)) for e in logs)


def test_dashboard_and_reports(client):
    headers = auth(client, ANALYST)
    dash = client.get(f"{API}/analytics/dashboard", headers=headers).json()
    assert {"totals", "trend", "by_category", "mtta_minutes", "sla_compliance_pct"} <= set(dash)
    assert len(dash["trend"]) == 30
    md = client.get(f"{API}/analytics/executive", headers=headers).text
    assert md.startswith("# Rapport exécutif") and "Banque Fictive du Sahel" in md
    bad = client.get(f"{API}/analytics/summary", params={"date_from": "2026-10-10T00:00:00", "date_to": "2026-10-01T00:00:00"},
                     headers=headers)
    assert bad.status_code == 400
    s = client.get(f"{API}/analytics/summary", params={"date_from": "2026-01-01T00:00:00"}, headers=headers).json()
    assert s["totals"]["incidents"] >= dash["totals"]["incidents"]
    assert json.dumps(s)  # serialisable
