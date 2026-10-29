"""Tenant isolation: one organisation must never see or touch another's data."""

from tests.conftest import ANALYST, LEAD, OTHER_ANALYST, OTHER_LEAD, SUPER, auth, new_incident

API = "/api/v1"


def test_incident_of_other_org_is_invisible(client):
    bfs = auth(client, ANALYST)
    mdn = auth(client, OTHER_ANALYST)
    inc = new_incident(client, bfs, title="Secret bancaire fictif")

    assert client.get(f"{API}/incidents/{inc['id']}", headers=mdn).status_code == 404
    assert client.patch(f"{API}/incidents/{inc['id']}", json={"title": "pwned"}, headers=mdn).status_code == 404
    assert client.post(f"{API}/incidents/{inc['id']}/comments", json={"message": "x"}, headers=mdn).status_code == 404
    listing = client.get(f"{API}/incidents", params={"q": "Secret bancaire", "size": 200}, headers=mdn).json()
    assert listing["total"] == 0


def test_cannot_assign_user_from_other_org(client):
    bfs = auth(client, ANALYST)
    mdn_user = client.get(f"{API}/auth/me", headers=auth(client, OTHER_ANALYST)).json()
    resp = client.post(f"{API}/incidents", headers=bfs,
                       json={"title": "Test assignation", "assignee_id": mdn_user["id"]})
    assert resp.status_code == 400


def test_cannot_link_ioc_across_orgs(client):
    bfs = auth(client, ANALYST)
    mdn = auth(client, OTHER_ANALYST)
    inc = new_incident(client, bfs)
    ioc = client.post(f"{API}/intel/iocs", json={"value": "isolation-test.example"}, headers=mdn).json()
    assert client.post(f"{API}/intel/iocs/{ioc['id']}/link/{inc['id']}", headers=mdn).status_code == 404
    assert client.post(f"{API}/intel/iocs/{ioc['id']}/link/{inc['id']}", headers=bfs).status_code == 404


def test_org_switch_header_reserved_to_super_admin(client):
    mdn_org = client.get(f"{API}/auth/me", headers=auth(client, OTHER_ANALYST)).json()["organization"]["id"]
    bfs = auth(client, ANALYST)
    assert client.get(f"{API}/incidents", headers={**bfs, "X-Organization-Id": mdn_org}).status_code == 403

    sup = {**auth(client, SUPER), "X-Organization-Id": mdn_org}
    listing = client.get(f"{API}/incidents", headers=sup)
    assert listing.status_code == 200
    assert listing.json()["total"] >= 10


def test_reports_and_decisions_are_scoped(client):
    bfs = auth(client, ANALYST)
    mdn_lead = auth(client, OTHER_LEAD)
    report_ids = [r["id"] for r in client.get(f"{API}/reports", headers=bfs).json()["items"]]
    assert report_ids
    assert client.get(f"{API}/reports/{report_ids[0]}", headers=mdn_lead).status_code == 404

    inc = new_incident(client, bfs, severity="critical")
    d = client.post(f"{API}/decisions", headers=bfs, json={
        "type": "external_escalation", "target_id": inc["id"], "justification": "Impact sur des services critiques"})
    assert d.status_code == 201
    review = client.post(f"{API}/decisions/{d.json()['id']}/review", json={"approve": True}, headers=mdn_lead)
    assert review.status_code == 404
    assert all(x["id"] != d.json()["id"] for x in client.get(f"{API}/decisions", headers=mdn_lead).json())


def test_community_iocs_hide_their_origin(client):
    bfs_analyst, bfs_lead = auth(client, ANALYST), auth(client, LEAD)
    mdn = auth(client, OTHER_ANALYST)
    ioc = client.post(f"{API}/intel/iocs", headers=bfs_analyst, json={
        "value": "partage-communautaire.example", "description": "contexte interne confidentiel", "tlp": "green"}).json()

    def community_values():
        items = client.get(f"{API}/intel/iocs", params={"include_community": True, "size": 500}, headers=mdn).json()["items"]
        return {i["value"]: i for i in items if i["is_community"]}

    assert "partage-communautaire.example" not in community_values()
    d = client.post(f"{API}/decisions", headers=bfs_analyst, json={
        "type": "share_ioc", "target_id": ioc["id"], "justification": "Domaine malveillant confirmé"}).json()
    assert client.post(f"{API}/decisions/{d['id']}/review", json={"approve": True}, headers=bfs_lead).status_code == 200

    shared = community_values()["partage-communautaire.example"]
    assert shared["source"] == "communauté"
    assert shared["description"] == ""
    assert shared["incident_refs"] == []
    # Visible, but still not modifiable by the other organisation.
    assert client.patch(f"{API}/intel/iocs/{ioc['id']}", json={"confidence": 1}, headers=mdn).status_code == 404
