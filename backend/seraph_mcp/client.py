"""Thin HTTP client the MCP tools share — every tool is a REST call against
a running Seraph instance, authenticated with a long-lived API token.

Required env vars:
  SERAPH_MCP_TOKEN     — an `srph_...` API token (Settings -> API Tokens in
                          Seraph itself). Never a JWT, never a password —
                          this is the same mechanism any other non-browser
                          client (e.g. Chronos) uses.
Optional:
  SERAPH_MCP_BASE_URL  — defaults to http://localhost:8000/api/v1
"""
import os

import httpx

_BASE_URL = os.environ.get("SERAPH_MCP_BASE_URL", "http://localhost:8000/api/v1")
_TOKEN = os.environ.get("SERAPH_MCP_TOKEN", "")


def _require_token() -> str:
    if not _TOKEN:
        raise RuntimeError(
            "SERAPH_MCP_TOKEN is not set. Create an API token in Seraph "
            "(Settings -> API Tokens) and set it in this server's environment."
        )
    return _TOKEN


async def request(method: str, path: str, *, json: dict | None = None, params: dict | None = None) -> dict:
    """Call `{SERAPH_MCP_BASE_URL}{path}` with the configured bearer token.

    No additional role-gating beyond what the wrapped REST endpoint itself
    already enforces — a token's privileges here are exactly whatever its
    owning user's role already grants on the real API, same as any other
    srph_-token caller.
    """
    token = _require_token()
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.request(
            method,
            f"{_BASE_URL}{path}",
            json=json,
            params={k: v for k, v in (params or {}).items() if v is not None},
            headers={"Authorization": f"Bearer {token}"},
        )
    if resp.status_code >= 400:
        try:
            detail = resp.json().get("detail", resp.text)
        except Exception:
            detail = resp.text
        raise RuntimeError(f"Seraph API error {resp.status_code}: {detail}")
    if resp.status_code == 204 or not resp.content:
        return {"ok": True}
    return resp.json()
