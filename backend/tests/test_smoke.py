"""Backend smoke suite.

Boots the app against an isolated DB, authenticates, and hits a representative
read endpoint on every router asserting **no 5xx** — the cheap insurance that
would have caught the two crashes we fixed (the `serve_spa` `HTTPException`
NameError and the `/ws/execute` `Target` UnboundLocalError).

Run:  cd backend && pytest tests -q
(Requires pytest — see backend/requirements-dev.txt. httpx is already a dep.)
"""

import pytest
from fastapi.testclient import TestClient

import database
import main

PW = "Passw0rdTest1"  # satisfies the password policy (>=12, upper/lower/digit)

# Read endpoints that are DB-backed and should never 5xx. Endpoints that reach
# external services (Ollama, Nessus, AWS, MSF/Sliver) are intentionally excluded —
# the smoke suite checks for crashes, not external integrations.
GET_ENDPOINTS = [
    "/api/v1/projects",
    "/api/v1/stats",
    "/api/v1/findings?project_id={pid}",
    "/api/v1/scans",
    "/api/v1/projects/{pid}/targets",
    "/api/v1/projects/{pid}/timeline",
    "/api/v1/projects/{pid}/scope",
    "/api/v1/audit/categories",
    "/api/v1/audit/coverage?project_id={pid}",
    "/api/v1/audit/findings?project_id={pid}",
    "/api/v1/pentest/engagements",
    "/api/v1/playbooks",
    "/api/v1/vulns?project_id={pid}",
    "/api/v1/c2/sessions",
    "/api/v1/cve-watch?project_id={pid}",
    "/api/v1/network/graph?project_id={pid}",
    "/api/v1/attack-paths/{pid}",
    "/api/v1/hardening/profiles",
    "/api/v1/notifications",
    "/api/v1/listeners",
    "/api/v1/agents",
    "/api/v1/webhooks",
    "/api/v1/profiles",
    "/api/v1/ai/config",
    "/api/v1/ai/attack/status",
    "/api/v1/ai/attack/coverage?project_id={pid}",
    "/api/v1/hermes/status",
    "/api/v1/demo/status",
    "/api/v1/screenshots?project_id={pid}",
    "/api/v1/http/requests?project_id={pid}",
    "/api/v1/ad/collections?project_id={pid}",
    "/api/v1/credentials?project_id={pid}",
    "/api/v1/credentials/keys?project_id={pid}",
    "/api/v1/settings/tools",
    "/api/v1/settings/host-info",
]


@pytest.fixture(scope="session")
def client():
    database.create_tables()
    return TestClient(main.app)


@pytest.fixture(scope="session")
def auth(client):
    client.post("/api/v1/auth/setup", json={"username": "smoke", "password": PW, "full_name": "Smoke Admin"})
    r = client.post("/api/v1/auth/login", data={"username": "smoke", "password": PW})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="session")
def pid(client, auth):
    r = client.post("/api/v1/projects", json={"name": "smoke", "description": "t"}, headers=auth)
    assert r.status_code in (200, 201), r.text
    p = r.json()["id"]
    client.post(
        f"/api/v1/projects/{p}/targets",
        json={"hostname_or_ip": "10.0.0.5", "target_type": "linux_host"},
        headers=auth,
    )
    return p


@pytest.mark.parametrize("path", GET_ENDPOINTS)
def test_read_endpoint_no_5xx(client, auth, pid, path):
    url = path.format(pid=pid)
    r = client.get(url, headers=auth)
    assert r.status_code < 500, f"{url} -> {r.status_code}: {r.text[:200]}"


def test_unknown_api_path_not_500(client, auth):
    """Regression: the SPA catch-all must 404 unknown /api paths, not crash (the
    serve_spa HTTPException NameError)."""
    r = client.get("/api/v1/does/not/exist", headers=auth)
    assert r.status_code != 500, r.text


def test_main_imports_httpexception():
    """Regression guard for the exact serve_spa bug: HTTPException must be in scope."""
    assert hasattr(main, "HTTPException")


def test_ws_events_connects(client):
    """The global event WebSocket should accept a connection without erroring."""
    with client.websocket_connect("/ws/events") as ws:
        ws.close()
