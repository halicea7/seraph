"""Contract test for the API's auth boundary.

CLAUDE.md's original framing of this app's auth model predates the
security pass: "No auth dependency is applied globally — individual
routers opt in with Depends(get_current_user)." main.py's auth_middleware
now enforces a Bearer token on every /api/v1/* request regardless of
whether the matched route has its own identity dependency, with a small,
explicit exempt list (login/setup, passkey begin/complete, agent
poll/result). That middleware decides purely on the request path's
prefix, before routing resolves to a handler — so the actual failure
mode this guards against isn't "a route forgot Depends(get_current_user)"
(the old model), it's "a router got mounted without the /api/v1 prefix"
(include_router called without prefix=API_PREFIX), which would make
every one of its endpoints unauthenticated by accident, invisible to any
single-route review.
"""
from fastapi.routing import APIRoute

import main
from test_smoke import client  # noqa: F401 — reuse the smoke suite's app/db fixture

# Routes genuinely meant to be reachable outside /api/v1 (the SPA itself,
# its static assets, FastAPI's own docs/schema endpoints, and the agent
# bootstrap short-URL, whose random short_code — not a bearer token — is
# deliberately the credential a brand-new, not-yet-authenticated machine
# uses to fetch its own install script) — anything else must live under
# /api/v1/ to be covered by auth_middleware.
_NON_API_ALLOWLIST = {"/", "/{full_path:path}", "/docs", "/redoc", "/openapi.json", "/a/{short_code}"}


def _http_routes():
    return [r for r in main.app.routes if isinstance(r, APIRoute)]


def test_every_http_route_is_under_api_v1_or_explicitly_allowlisted():
    stray = [
        r.path for r in _http_routes()
        if not r.path.startswith("/api/v1/") and r.path not in _NON_API_ALLOWLIST
    ]
    assert not stray, (
        f"these routes are outside /api/v1/ and not on the allowlist, so "
        f"auth_middleware's prefix check never covers them: {stray}"
    )


def test_sample_of_sensitive_endpoints_reject_unauthenticated_requests(client):
    sensitive_get_paths = [
        "/api/v1/projects",
        "/api/v1/credentials?project_id=x",
        "/api/v1/c2/sessions",
        "/api/v1/settings/tools",
        "/api/v1/notifications",
        "/api/v1/agents",
    ]
    for path in sensitive_get_paths:
        r = client.get(path)
        assert r.status_code == 401, f"{path} must require auth, got {r.status_code}"
