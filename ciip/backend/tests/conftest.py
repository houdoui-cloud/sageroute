import os
import tempfile

# Configure before the app is imported: isolated DB, no Redis, no LLM.
_tmp = tempfile.mkdtemp(prefix="ciip-test-")
os.environ.setdefault("CIIP_DATABASE_URL", os.environ.get("CIIP_TEST_DATABASE_URL", f"sqlite:///{_tmp}/test.db"))
os.environ["CIIP_REDIS_URL"] = ""
os.environ["CIIP_AI_USE_OLLAMA"] = "false"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core.kv import MemoryKV, set_kv  # noqa: E402
from app.db import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.seed import DEMO_PASSWORD, seed  # noqa: E402

PASSWORD = DEMO_PASSWORD


@pytest.fixture(scope="session", autouse=True)
def _database():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        seed(db)
    yield
    Base.metadata.drop_all(engine)


@pytest.fixture(autouse=True)
def _fresh_kv():
    set_kv(MemoryKV())
    yield


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def db():
    with SessionLocal() as session:
        yield session


def token(client: TestClient, email: str) -> str:
    resp = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def auth(client: TestClient, email: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token(client, email)}"}


ANALYST = "analyste@bfs.example"
ANALYST2 = "analyste2@bfs.example"
LEAD = "lead@bfs.example"
ADMIN = "admin@bfs.example"
REPORTER = "declarant@bfs.example"
AUDITOR = "auditeur@bfs.example"
SUPER = "superadmin@ciip.example"
OTHER_ANALYST = "analyste@mdn.example"
OTHER_LEAD = "lead@mdn.example"


def new_incident(client: TestClient, headers: dict, **overrides) -> dict:
    body = {"title": "Incident de test", "description": "Description fictive", "category": "phishing",
            "severity": "medium", **overrides}
    resp = client.post("/api/v1/incidents", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()
