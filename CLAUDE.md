# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Development (both services together)
```bash
./dev.sh                          # starts backend :8000 + frontend :22123
```

### Backend only
```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend only
```bash
cd frontend
npm run dev       # Vite dev server on :22123 (proxies /api and /ws to :8000)
npm run build     # production build into frontend/dist/ (served by FastAPI)
npx tsc --noEmit  # type-check without building
```

There are no automated tests. Type-check the frontend before building.

## Architecture

Seraph is a single-repo, two-process app. The FastAPI backend serves both the REST/WebSocket API and (in production) the pre-built React SPA from `frontend/dist/`.

### Data flow
```
Browser → Vite proxy (dev) or FastAPI static (prod)
       → REST  /api/v1/...   → FastAPI routers → SQLAlchemy → SQLite
       → WS    /ws/...       → FastAPI WS routes → subprocess executor → streamed output
```

### Backend (`backend/`)

**Entry point:** `main.py` — registers all routers under `/api/v1`, mounts `frontend/dist/` for SPA fallback, runs startup hooks (create tables, detect tools, seed built-in playbooks, start scheduler).

**Database:** `database.py` defines all SQLAlchemy models. The cascade chain is:
`Project → Target → Scan → Finding` (SQLAlchemy cascade).
`VulnerabilityRecord` and `Credential` hold `project_id` FKs but are **not** in the cascade — they must be explicitly deleted before deleting a project (see `routers/demo.py` for the pattern).

**Schema migrations** are handled by `_migrate()` in `database.py` — a list of `ALTER TABLE` statements that are silently skipped if the column already exists. Add new columns here; never drop tables. New columns must be added both to the model class and to the `_migrate()` list.

**Routers of note:**
- `projects.py` — also contains the `stats_router` (mounted separately) with `/stats`, `/findings`, and `/scans` cross-project list endpoints.
- `ws.py` — WebSocket relay; `execute` waits for a `{"action":"run","script":"..."}` message then streams subprocess output line-by-line as `{"type":"stdout"|"stderr"|"exit","data":"..."}`.
- `demo.py` — seeds/clears three demo projects identified by `description == "__seraph_demo__"`.
- `auth.py` — uses `get_current_user` (OAuth2 Bearer) as a FastAPI `Depends`; routes that don't call it are unauthenticated.

**Services:**
- `executor.py` — async subprocess runner used by all WebSocket routes.
- `tool_registry.py` — `shutil.which` + version detection; called on startup and via `GET /api/v1/settings/tools`.
- `playbook_runner.py` — executes `Playbook.steps_json` sequentially or in step-through mode, streaming per step over `/ws/playbooks/{run_id}`.
- `scheduler.py` — APScheduler wrapping `ScanProfile.schedule` (cron string); reschedules on startup.
- `ai_client.py` — thin wrapper around the configured LLM endpoint (Ollama by default); used by `/vulns/{id}/ai-remediate` and `/logs/ai-triage`.

**Auth:** JWT Bearer tokens, 24 h expiry, signed with `SERAPH_SECRET_KEY` env var. If unset, a random key is generated per-process (sessions reset on restart) and a warning is logged. No auth dependency is applied globally — individual routers opt in with `Depends(get_current_user)`. Most read endpoints are currently unauthenticated.

**User model** has `full_name` (nullable). `PATCH /auth/me` lets any authenticated user update their own `full_name`. `POST /auth/users` and `POST /auth/setup` also accept `full_name`. `_user_dict()` always returns `full_name` (empty string if null).

**Metasploit RPC** password comes from `MSF_RPC_PASSWORD` env var (see `.env.example`). The `ConnectRequest` default is an empty string; `msf_client.connect()` reads the env var as fallback.

### Frontend (`frontend/src/`)

**State:** Zustand store (`stores/appStore.ts`) holds `projects[]` and `selectedProject`. Everything else is local component state fetched on mount.

**API calls:** All REST calls go through `api/client.ts` using `BASE_URL = '/api/v1'` (relative). WebSocket URLs are constructed as `${wsProto}//${window.location.host}/ws/...` — never hardcode `localhost:8000`.

**Auth:** `AuthContext` stores the JWT in `localStorage` under `seraph_token` and attaches it as `Authorization: Bearer <token>` on `/api/v1/auth/me` at startup. The `api/client.ts` helper does **not** automatically attach the token — auth-required pages call `fetch` directly with the header. `AuthContext` exposes `refreshUser()` to re-fetch `/auth/me` and update in-memory user state (call after profile edits).

**Routing:** `App.tsx` wraps everything in `<AuthGate>` → `<ProtectedRoutes>` → `<Layout>` (sidebar) → page outlet. Unauthenticated users are redirected to `/login`; authenticated users hitting `/login` are redirected to `/`.

**Themes:** `ThemeContext` toggles a `data-theme="mono"` attribute on `<html>`. Mono overrides live in `index.css` as attribute-selector rules (e.g. `[data-theme="mono"] .class`). Tailwind JIT classes with special characters need escaped brackets: `.bg-\[\#hex\]` not `.bg-[#hex]`.

**Terminal (xterm.js):** `components/Terminal.tsx` creates one `xterm.Terminal` per `scanId` prop change, connects over WebSocket, and sends `{"action":"run","script":"..."}` to start execution. The xterm theme must be set via `term.options.theme` (not CSS) because the canvas renderer ignores stylesheets.

### Key conventions

- All primary keys are UUIDs (`str(uuid.uuid4())`), generated in Python.
- Scan `config_json` and Playbook `steps_json` are stored as JSON strings; parse with `json.loads` before use.
- The `AppSetting` table is a simple key/value store used for feature flags (`demo_mode`, `auto_probe_enabled`, AI endpoint config, etc.).
- Demo data is identified exclusively by `Project.description == "__seraph_demo__"`.
- Report generation flows: `POST /audit/reports/generate` → `services/report_generator.py` → Jinja2 templates in `backend/templates/reports/`. The `auditor` field passes from the request body through to the template context. `GET /audit/reports/download/{id}` accepts `auditor` as a query param. The `Reports.tsx` page auto-populates the auditor field from `user.full_name` (falls back to `user.username`).
- `Notification` rows have a `scan_id` column (nullable). When set, clicking the notification in `NotificationBell` navigates to `/scans?open=<scan_id>`, which `AllScans.tsx` reads on mount to auto-open that scan's drawer.
