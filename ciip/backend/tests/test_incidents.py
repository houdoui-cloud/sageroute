import re
from datetime import timedelta

from app.models import Incident, Severity, utcnow
from app.services.incidents import apply_sla, is_sla_breached
from tests.conftest import ANALYST, ANALYST2, LEAD, auth, new_incident

API = "/api/v1"


def test_create_assigns_reference_and_sla(client):
    inc = new_incident(client, auth(client, ANALYST), severity="critical")
    assert re.fullmatch(r"INC-\d{4}-\d{4}", inc["reference"])
    assert inc["status"] == "new"
    assert inc["sla_ack_due"] and inc["sla_resolve_due"]
    assert inc["events"][0]["kind"] == "created"


def test_references_are_sequential(client):
    headers = auth(client, ANALYST)
    a, b = new_incident(client, headers), new_incident(client, headers)
    assert int(b["reference"][-4:]) == int(a["reference"][-4:]) + 1


def test_lifecycle_and_invalid_transition(client):
    headers = auth(client, ANALYST)
    inc = new_incident(client, headers)
    url = f"{API}/incidents/{inc['id']}/status"
    assert client.post(url, json={"status": "resolved"}, headers=headers).status_code == 409
    r = client.post(url, json={"status": "in_progress"}, headers=headers).json()
    assert r["acknowledged_at"] is not None
    client.post(url, json={"status": "contained"}, headers=headers)
    r = client.post(url, json={"status": "resolved", "comment": "Correctif appliqué"}, headers=headers).json()
    assert r["resolved_at"] is not None
    r = client.post(url, json={"status": "closed"}, headers=headers).json()
    assert r["status"] == "closed"
    kinds = [e["kind"] for e in r["events"]]
    assert kinds.count("status_change") == 4


def test_critical_close_requires_approved_decision(client):
    analyst, lead = auth(client, ANALYST), auth(client, LEAD)
    inc = new_incident(client, analyst, severity="critical")
    for s in ("in_progress", "resolved"):
        client.post(f"{API}/incidents/{inc['id']}/status", json={"status": s}, headers=analyst)
    direct = client.post(f"{API}/incidents/{inc['id']}/status", json={"status": "closed"}, headers=analyst)
    assert direct.status_code == 409

    d = client.post(f"{API}/decisions", headers=analyst, json={
        "type": "close_critical_incident", "target_id": inc["id"], "justification": "Systèmes restaurés et vérifiés"})
    assert d.status_code == 201
    detail = client.get(f"{API}/incidents/{inc['id']}", headers=analyst).json()
    assert detail["pending_decisions"] == 1 and detail["status"] == "resolved"

    assert client.post(f"{API}/decisions/{d.json()['id']}/review", json={"approve": True}, headers=lead).status_code == 200
    assert client.get(f"{API}/incidents/{inc['id']}", headers=analyst).json()["status"] == "closed"


def test_escalation_rules(client):
    headers = auth(client, ANALYST)
    inc = new_incident(client, headers)
    url = f"{API}/incidents/{inc['id']}/escalate"
    r = client.post(url, json={"to_level": "L2", "reason": "Besoin d'expertise forensique"}, headers=headers)
    assert r.status_code == 200 and r.json()["escalation_level"] == "L2"
    assert client.post(url, json={"to_level": "L1", "reason": "Retour arrière"}, headers=headers).status_code == 409
    ext = client.post(url, json={"to_level": "external", "reason": "Notification CERT"}, headers=headers)
    assert ext.status_code == 409
    history = client.get(f"{API}/incidents/{inc['id']}/escalations", headers=headers).json()
    assert [h["to_level"] for h in history] == ["L2"]


def test_external_escalation_via_decision(client):
    analyst, lead = auth(client, ANALYST), auth(client, LEAD)
    inc = new_incident(client, analyst, severity="high")
    d = client.post(f"{API}/decisions", headers=analyst, json={
        "type": "external_escalation", "target_id": inc["id"], "justification": "Infrastructure critique touchée"}).json()
    r = client.post(f"{API}/decisions/{d['id']}/review", json={"approve": True, "comment": "OK"}, headers=lead).json()
    assert r["status"] == "approved"
    detail = client.get(f"{API}/incidents/{inc['id']}", headers=analyst).json()
    assert detail["escalation_level"] == "external"
    assert any("CERT-DEMO-" in e["message"] for e in detail["events"])


def test_assign_comment_and_update(client):
    headers = auth(client, ANALYST)
    inc = new_incident(client, headers, severity="low")
    other = client.get(f"{API}/auth/me", headers=auth(client, ANALYST2)).json()
    r = client.post(f"{API}/incidents/{inc['id']}/assign", json={"assignee_id": other["id"]}, headers=headers).json()
    assert r["assignee"]["id"] == other["id"]
    r = client.post(f"{API}/incidents/{inc['id']}/comments", json={"message": "Analyse en cours"}, headers=headers)
    assert r.status_code == 201
    old_due = inc["sla_resolve_due"]
    r = client.patch(f"{API}/incidents/{inc['id']}", json={"severity": "critical"}, headers=headers).json()
    assert r["severity"] == "critical" and r["sla_resolve_due"] != old_due
    assert any(e["kind"] == "severity_change" for e in r["events"])


def test_list_filters_and_export(client):
    headers = auth(client, ANALYST)
    new_incident(client, headers, title="Filtrage unique zebra", severity="low")
    res = client.get(f"{API}/incidents", params={"q": "zebra"}, headers=headers).json()
    assert res["total"] == 1
    res = client.get(f"{API}/incidents", params={"severity": "low", "q": "zebra"}, headers=headers).json()
    assert res["total"] == 1
    res = client.get(f"{API}/incidents", params={"severity": "high", "q": "zebra"}, headers=headers).json()
    assert res["total"] == 0
    csv = client.get(f"{API}/incidents/export.csv", headers=headers)
    assert csv.status_code == 200 and "zebra" in csv.text


def test_sla_breach_logic():
    inc = Incident(severity=Severity.CRITICAL, status="new", created_at=utcnow() - timedelta(minutes=30))
    apply_sla(inc)
    assert is_sla_breached(inc)
    inc2 = Incident(severity=Severity.LOW, status="new", created_at=utcnow())
    apply_sla(inc2)
    assert not is_sla_breached(inc2)
