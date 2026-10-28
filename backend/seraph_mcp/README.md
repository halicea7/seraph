# Seraph MCP connector

A local stdio [MCP](https://modelcontextprotocol.io) server exposing Seraph's
REST API as tools — list projects, create targets, trigger/parse scans, read
and triage findings, manage credentials, run C2 post-exploitation modules.

It is a client of the Seraph API, not part of it: it runs as its own process,
never imports the backend app, and authenticates like any other `srph_...`
API-token caller. A token's privileges here are exactly whatever its owning
user's role already grants on the real API — no additional gating.

## Setup

1. In Seraph: **Settings → API Tokens** → create a token. Copy it (`srph_...`).
2. Install the connector's own dependencies, in their **own** virtualenv —
   see the comment at the top of `requirements.txt` for why this must not
   share an environment with `backend/requirements.txt`:
   ```bash
   cd backend/seraph_mcp
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
3. Point an MCP client at it. Example Claude Desktop/Claude Code config
   (`claude_desktop_config.json` or equivalent):
   ```json
   {
     "mcpServers": {
       "seraph": {
         "command": "/absolute/path/to/seraph/backend/seraph_mcp/.venv/bin/python",
         "args": ["-m", "seraph_mcp"],
         "cwd": "/absolute/path/to/seraph/backend",
         "env": {
           "SERAPH_MCP_TOKEN": "srph_...",
           "SERAPH_MCP_BASE_URL": "http://localhost:8000/api/v1"
         }
       }
     }
   }
   ```
   `cwd` must be `backend/` so `seraph_mcp` resolves as a top-level package.
   `SERAPH_MCP_BASE_URL` defaults to `http://localhost:8000/api/v1` if omitted.

## Tool coverage

Tools are grouped by the router they wrap (projects, targets, scans,
findings, credentials, C2, notifications) — see `server.py`. This covers
the core engagement workflow end to end, not literally every REST endpoint;
adding a new tool is a matter of adding one more thin `request(...)` call
following the existing pattern.

Running a generated audit script is intentionally not a tool here — that
happens interactively over Seraph's `/ws/execute/{scan_id}` WebSocket in the
Seraph UI/terminal, which this stdio connector doesn't drive. `generate_audit_script`
exists so an MCP client can prepare/preview one.
