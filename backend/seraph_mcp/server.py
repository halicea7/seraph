"""Seraph MCP tool definitions, grouped by the REST router each wraps.

Each tool is a thin pass-through to the real Seraph API (see client.py) --
no logic, no caching, no extra validation beyond what the endpoint itself
does. This is intentional: the tool surface should track the REST API
exactly, so a capability added to the API shows up here the same way, and
nothing here can diverge from what the real endpoint actually enforces.
"""
from typing import Optional

from mcp.server.mcpserver import MCPServer

from seraph_mcp.client import request

mcp = MCPServer(
    name="seraph",
    instructions=(
        "Tools for Seraph, a pentest/audit engagement tracker. Covers "
        "projects, targets, scans, findings, credentials, C2 sessions, and "
        "notifications. Requires SERAPH_MCP_TOKEN to be set in this "
        "server's environment to an API token created in Seraph's "
        "Settings -> API Tokens."
    ),
)


# ── Projects ──────────────────────────────────────────────────────────────────

@mcp.tool()
async def list_projects() -> dict:
    """List all Seraph projects (engagements)."""
    return {"projects": await request("GET", "/projects")}


@mcp.tool()
async def get_project(project_id: str) -> dict:
    """Get a single project's details, including its targets."""
    return await request("GET", f"/projects/{project_id}")


@mcp.tool()
async def create_project(name: str, description: str = "") -> dict:
    """Create a new project (engagement)."""
    return await request("POST", "/projects", json={"name": name, "description": description})


@mcp.tool()
async def get_project_scope(project_id: str) -> dict:
    """Get a project's configured scope (include/exclude host patterns)."""
    return await request("GET", f"/projects/{project_id}/scope")


@mcp.tool()
async def update_project_scope(project_id: str, include: list[str], exclude: Optional[list[str]] = None) -> dict:
    """Set a project's scope. `include`/`exclude` entries may be CIDR
    ranges, exact hostnames, or wildcard patterns. An empty `include`
    means everything is in scope."""
    return await request(
        "PUT", f"/projects/{project_id}/scope",
        json={"include": include, "exclude": exclude or []},
    )


# ── Targets ───────────────────────────────────────────────────────────────────

@mcp.tool()
async def list_targets(project_id: str) -> dict:
    """List a project's targets."""
    return {"targets": await request("GET", f"/projects/{project_id}/targets")}


@mcp.tool()
async def create_target(project_id: str, hostname_or_ip: str, target_type: str, notes: str = "") -> dict:
    """Add a target to a project. target_type is one of: linux_host,
    windows_host, web_app, cloud_aws, cloud_azure, cloud_gcp, network,
    api_endpoint. Rejected with 400 if out of the project's scope or if a
    target with the same hostname/IP already exists in this project."""
    return await request(
        "POST",
        f"/projects/{project_id}/targets",
        json={"hostname_or_ip": hostname_or_ip, "target_type": target_type, "notes": notes},
    )


# ── Scans / audit scripts ─────────────────────────────────────────────────────

@mcp.tool()
async def list_scans(project_id: Optional[str] = None, status: Optional[str] = None, limit: int = 50) -> dict:
    """List scans, optionally filtered by project_id and/or status
    (pending/running/completed/failed)."""
    return {"scans": await request("GET", "/scans", params={"project_id": project_id, "status": status, "limit": limit})}


@mcp.tool()
async def get_scan(scan_id: str) -> dict:
    """Get a single scan's full record, including raw_output and
    provenance_json if it has run."""
    return await request("GET", f"/audit/scans/{scan_id}")


@mcp.tool()
async def generate_audit_script(project_id: str, target_id: str, scan_categories: list[dict]) -> dict:
    """Generate (but do not run) an audit script for a target. Returns
    {scan_id, script}. scan_categories is a list of
    {"category_id": str, "config": dict} -- category_id is one of:
    network_discovery, vulnerability_scan, web_audit, host_hardening,
    openscap, cloud_aws, log_monitoring. Actually running the generated
    script happens over Seraph's /ws/execute/{scan_id} WebSocket, which
    this connector does not drive -- use the Seraph UI/terminal for that;
    this tool is for previewing/queuing what a scan would run."""
    return await request(
        "POST",
        "/audit/generate",
        json={"project_id": project_id, "target_id": target_id, "scan_categories": scan_categories},
    )


@mcp.tool()
async def parse_scan_findings(scan_id: str) -> dict:
    """(Re-)parse a scan's raw_output into Finding rows. Upserts by
    fingerprint, so calling this again after a rescan never wipes
    existing triage (status/tags/fp_reason) on findings still present."""
    return await request("POST", f"/audit/scans/{scan_id}/parse")


@mcp.tool()
async def cancel_scan(scan_id: str) -> dict:
    """Cancel a running or pending scan."""
    return await request("POST", f"/scans/{scan_id}/cancel")


# ── Findings ──────────────────────────────────────────────────────────────────

@mcp.tool()
async def list_findings(project_id: Optional[str] = None, severity: Optional[str] = None,
                         limit: int = 100, offset: int = 0) -> dict:
    """List findings across all scans, optionally filtered by project_id
    and/or severity (critical/high/medium/low/info)."""
    return {"findings": await request(
        "GET", "/findings",
        params={"project_id": project_id, "severity": severity, "limit": limit, "offset": offset},
    )}


@mcp.tool()
async def update_finding_status(finding_id: str, status: str) -> dict:
    """Update a finding's triage status: open, in-review, remediated,
    accepted, or false_positive."""
    return await request("PATCH", f"/findings/{finding_id}/status", json={"status": status})


@mcp.tool()
async def suppress_finding(finding_id: str, reason: str) -> dict:
    """Mark a finding as a false positive with a reason."""
    return await request("POST", f"/findings/{finding_id}/suppress", json={"reason": reason})


# ── Credentials ───────────────────────────────────────────────────────────────

@mcp.tool()
async def list_credentials(project_id: str) -> dict:
    """List a project's stored credentials. Secrets are never included --
    call reveal_credential explicitly for the plaintext value."""
    return {"credentials": await request("GET", "/credentials", params={"project_id": project_id})}


@mcp.tool()
async def reveal_credential(credential_id: str) -> dict:
    """Reveal a credential's plaintext secret. This is an audited action
    on the Seraph side (routers/credentials.py) -- use deliberately."""
    return await request("POST", f"/credentials/{credential_id}/reveal")


@mcp.tool()
async def create_credential(project_id: str, username: str, secret: str, cred_type: str = "password",
                             source: str = "manual", target_host: str = "", notes: str = "") -> dict:
    """Store a credential. cred_type is one of: password, hash, key,
    token, other. source is one of: manual, c2_loot, osint, brute_force."""
    return await request(
        "POST", "/credentials",
        json={
            "project_id": project_id, "username": username, "secret": secret,
            "cred_type": cred_type, "source": source, "target_host": target_host, "notes": notes,
        },
    )


# ── C2 ────────────────────────────────────────────────────────────────────────

@mcp.tool()
async def list_c2_sessions(project_id: Optional[str] = None) -> dict:
    """List active/known C2 (Metasploit/Sliver) sessions."""
    return {"sessions": await request("GET", "/c2/sessions", params={"project_id": project_id})}


@mcp.tool()
async def run_c2_post_module(session_id: str, module_name: str, options: Optional[dict] = None) -> dict:
    """Run a Metasploit post-exploitation module against a C2 session.
    module_name must match ^post/[\\w/]+$ (e.g. post/multi/recon/local_exploit_suggester)."""
    return await request(
        "POST", "/c2/post-modules/run",
        json={"session_id": session_id, "module_name": module_name, "options": options or {}},
    )


# ── Notifications ─────────────────────────────────────────────────────────────

@mcp.tool()
async def list_notifications(unread_only: bool = False) -> dict:
    """List Seraph's in-app notifications."""
    return {"notifications": await request("GET", "/notifications", params={"unread_only": unread_only})}
