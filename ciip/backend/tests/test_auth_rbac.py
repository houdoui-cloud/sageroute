from tests.conftest import ADMIN, ANALYST, AUDITOR, LEAD, PASSWORD, REPORTER, auth, new_incident

API = "/api/v1"


def test_login_and_me(client):
    headers = auth(client, ANALYST)
    me = client.get(f"{API}/auth/me", headers=headers).json()
    assert me["role"] == "analyst"
    assert me["organization"]["slug"] == "bfs"
    assert "incident:write" in me["permissions"]
    assert "decision:approve" not in me["permissions"]


def test_login_errors_are_generic(client):
    unknown = client.post(f"{API}/auth/login", json={"email": "nobody@bfs.example", "password": "x"})
    wrong = client.post(f"{API}/auth/login", json={"email": ANALYST, "password": "wrong"})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()


def test_lockout_after_repeated_failures(client):
    email = "analyste2@bfs.example"
    for _ in range(5):
        assert client.post(f"{API}/auth/login", json={"email": email, "password": "bad"}).status_code == 401
    # Even the right password is refused while locked.
    resp = client.post(f"{API}/auth/login", json={"email": email, "password": PASSWORD})
    assert resp.status_code == 423
    from app.db import SessionLocal
    from app.models import User
    with SessionLocal() as db:
        user = db.query(User).filter_by(email=email).one()
        user.locked_until = None
        db.commit()


def test_logout_revokes_access_token(client):
    headers = auth(client, ANALYST)
    assert client.post(f"{API}/auth/logout", headers=headers).status_code == 204
    assert client.get(f"{API}/auth/me", headers=headers).status_code == 401


def test_refresh_token_is_single_use(client):
    tokens = client.post(f"{API}/auth/login", json={"email": ANALYST, "password": PASSWORD}).json()
    first = client.post(f"{API}/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert first.status_code == 200
    again = client.post(f"{API}/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert again.status_code == 401
    # An access token is not accepted as a refresh token.
    assert client.post(f"{API}/auth/refresh", json={"refresh_token": tokens["access_token"]}).status_code == 401


def test_missing_or_garbage_token(client):
    assert client.get(f"{API}/incidents").status_code == 401
    assert client.get(f"{API}/incidents", headers={"Authorization": "Bearer abc"}).status_code == 401


def test_reporter_cannot_read_incidents(client):
    assert client.get(f"{API}/incidents", headers=auth(client, REPORTER)).status_code == 403


def test_auditor_is_read_only(client):
    headers = auth(client, AUDITOR)
    assert client.get(f"{API}/incidents", headers=headers).status_code == 200
    assert client.post(f"{API}/incidents", json={"title": "x" * 5}, headers=headers).status_code == 403
    assert client.get(f"{API}/admin/audit", headers=headers).status_code == 200


def test_analyst_cannot_manage_users_or_validate(client):
    headers = auth(client, ANALYST)
    assert client.get(f"{API}/admin/users", headers=headers).status_code == 403
    inc = new_incident(client, headers)
    sug = client.post(f"{API}/ai/triage", json={"incident_id": inc["id"]}, headers=headers).json()
    resp = client.post(f"{API}/ai/suggestions/{sug['id']}/review", json={"approve": True}, headers=headers)
    assert resp.status_code == 403


def test_org_admin_user_management(client):
    headers = auth(client, ADMIN)
    weak = client.post(f"{API}/admin/users", headers=headers,
                       json={"email": "new@bfs.example", "full_name": "Nouvel Agent", "role": "analyst",
                             "password": "short"})
    assert weak.status_code == 422
    escalate = client.post(f"{API}/admin/users", headers=headers,
                           json={"email": "root@bfs.example", "full_name": "Root", "role": "super_admin",
                                 "password": "Sufficiently1Strong"})
    assert escalate.status_code == 403
    ok = client.post(f"{API}/admin/users", headers=headers,
                     json={"email": "New.Agent@bfs.example", "full_name": "Nouvel Agent", "role": "analyst",
                           "password": "Sufficiently1Strong"})
    assert ok.status_code == 201
    assert ok.json()["email"] == "new.agent@bfs.example"
    me = client.get(f"{API}/auth/me", headers=headers).json()
    self_demote = client.patch(f"{API}/admin/users/{me['id']}", json={"role": "analyst"}, headers=headers)
    assert self_demote.status_code == 400


def test_lead_can_read_pii_analyst_cannot(client):
    lead = client.get(f"{API}/auth/me", headers=auth(client, LEAD)).json()
    analyst = client.get(f"{API}/auth/me", headers=auth(client, ANALYST)).json()
    assert "pii:read" in lead["permissions"]
    assert "pii:read" not in analyst["permissions"]


def test_security_headers(client):
    resp = client.get("/api/health")
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
