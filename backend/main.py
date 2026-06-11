import os
import time
import asyncio
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from config import settings
from database import create_tables
from routers.audit import router as audit_router
from routers.pentest import router as pentest_router
from routers.profiles import router as profiles_router
from routers.diff import router as diff_router
from routers.projects import router as projects_router
from routers.projects import targets_router
from routers.projects import stats_router
from routers.ws import router as ws_router
from routers.c2 import router as c2_router
from routers.cracking import router as cracking_router
from routers.enrichment import router as enrichment_router
from routers.network import router as network_router
from routers.osint import router as osint_router
from routers.credentials import router as credentials_router
from routers.evidence import router as evidence_router
from routers.ai import router as ai_router
from routers.auth import router as auth_router
from routers.passkeys import router as passkeys_router
from routers.playbooks import router as playbooks_router
from routers.vulns import router as vulns_router
from routers.logs import router as logs_router
from routers.hardening import router as hardening_router
from routers.demo import router as demo_router
from routers.notifications import router as notifications_router
from routers.listeners import router as listeners_router
from routers.agents import router as agents_router
from routers.webhooks import router as webhooks_router
from routers.attack_paths import router as attack_paths_router
from routers.cve_watch import router as cve_watch_router
from routers.attack import router as attack_router
from routers.ptes import router as ptes_router
from routers.nessus import router as nessus_router
from routers.hermes import router as hermes_router
from routers.cloud import router as cloud_router
from services.tool_registry import detect_tools, initialize_registry
from services.scheduler import initialize_scheduler
from services.playbook_runner import seed_builtin_playbooks
from services.listener_manager import initialize_listeners
from services.attack_index import ensure_fts_table, sync_if_empty
from services.ptes_index import ensure_fts_table as ptes_ensure, sync_if_empty as ptes_sync_if_empty


def _reset_stale_scans():
    """Mark any scans left in running/pending state as failed — they died with the previous process."""
    from database import get_db, Scan
    db = next(get_db())
    try:
        stale = db.query(Scan).filter(Scan.status.in_(["running", "pending"])).all()
        for scan in stale:
            scan.status = "failed"
        if stale:
            db.commit()
            import logging
            logging.getLogger(__name__).info("Reset %d stale scans to 'failed' on startup", len(stale))
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    create_tables()
    _reset_stale_scans()
    initialize_registry()
    initialize_scheduler()
    initialize_listeners()
    seed_builtin_playbooks()
    ensure_fts_table()
    sync_if_empty()
    ptes_ensure()
    ptes_sync_if_empty()
    yield
    # Shutdown (nothing to clean up)


app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    lifespan=lifespan,
)

# CORS — WebAuthn-trusted origins for cookie-based flows; all other origins are
# permitted via regex because Electron (Origin: null) and LAN clients send
# unpredictable origins. API-token auth is the real gate for those callers.
_cors_origins = [o.strip() for o in settings.rp_origins.split(",") if o.strip()]
if settings.extra_cors_origins:
    _cors_origins += [o.strip() for o in settings.extra_cors_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_origin_regex=r".*",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Accept", "Accept-Language", "Authorization", "Content-Language", "Content-Type", "X-Requested-With"],
)

# ── Rate limiting middleware ──────────────────────────────────────────────────

# Simple sliding-window rate limiter.
# Configurable via env vars:
#   SERAPH_RATE_LIMIT_REQUESTS  — max requests per window (default: 300)
#   SERAPH_RATE_LIMIT_WINDOW    — window in seconds (default: 60)
#   SERAPH_RATE_LIMIT_BURST     — burst multiplier for authenticated requests (default: 5)
#
# Routes exempted from rate limiting:
#   - WebSocket connections (/ws/*)
#   - Static assets (/assets/*)
#   - Health check (/)

_rate_window = int(os.environ.get("SERAPH_RATE_LIMIT_WINDOW", "60"))
_rate_max = int(os.environ.get("SERAPH_RATE_LIMIT_REQUESTS", "300"))
# Per-IP request timestamps (pruned when old)
_rate_store: dict[str, list[float]] = defaultdict(list)
_rate_lock = asyncio.Lock()


def _get_client_ip(request: Request) -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    path = request.url.path
    # Exempt WebSocket upgrades and static assets
    if path.startswith("/ws/") or path.startswith("/assets/") or path == "/":
        return await call_next(request)

    ip = _get_client_ip(request)
    now = time.monotonic()
    cutoff = now - _rate_window

    async with _rate_lock:
        # Prune old timestamps
        timestamps = _rate_store[ip]
        _rate_store[ip] = [t for t in timestamps if t > cutoff]
        count = len(_rate_store[ip])

        if count >= _rate_max:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please slow down."},
                headers={"Retry-After": str(_rate_window)},
            )
        _rate_store[ip].append(now)

    return await call_next(request)


# ── Audit log middleware ──────────────────────────────────────────────────────
#
# Writes one row to audit_log for every mutating API request (POST/PUT/PATCH/DELETE)
# that hits /api/v1/*. Reads are NOT logged to keep the table small.
# The JWT is decoded to extract user_id without going through the full auth stack.

_AUDIT_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_AUDIT_PATH_PREFIX = "/api/v1/"
_AUDIT_SKIP_PATHS = {
    "/api/v1/auth/login",   # already logged by brute-force tracker
    "/api/v1/auth/logout",
}


def _extract_user_id_from_request(request: Request) -> str | None:
    """Peek at the Authorization header and decode the JWT jti/sub without validation."""
    from services.auth_service import decode_token
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.removeprefix("Bearer ").strip()
    try:
        payload = decode_token(token)
        return str(payload.get("sub", ""))
    except Exception:
        return None


def _derive_resource(path: str) -> tuple[str | None, str | None]:
    """Return (resource_type, resource_id) from a URL path like /api/v1/projects/abc123."""
    parts = [p for p in path.split("/") if p]
    # parts[0]="api", [1]="v1", [2]=resource_type, [3]=id (optional)
    rtype = parts[2] if len(parts) > 2 else None
    rid = parts[3] if len(parts) > 3 else None
    return rtype, rid


@app.middleware("http")
async def audit_log_middleware(request: Request, call_next):
    method = request.method
    path = request.url.path

    # Only audit mutating requests to /api/v1/
    if method not in _AUDIT_METHODS or not path.startswith(_AUDIT_PATH_PREFIX) or path in _AUDIT_SKIP_PATHS:
        return await call_next(request)

    response = await call_next(request)

    # Only log successful mutations (2xx)
    if response.status_code < 200 or response.status_code >= 300:
        return response

    try:
        from database import SessionLocal, AuditLog as _AuditLog
        user_id = _extract_user_id_from_request(request)
        ip = _get_client_ip(request)
        rtype, rid = _derive_resource(path)
        db = SessionLocal()
        try:
            db.add(_AuditLog(
                action=f"{method} {path}",
                user_id=user_id,
                resource_type=rtype,
                resource_id=rid,
                ip_address=ip,
            ))
            db.commit()
        finally:
            db.close()
    except Exception:
        pass  # audit failures never block requests

    return response


# ── API routers ───────────────────────────────────────────────────────────────

API_PREFIX = "/api/v1"

app.include_router(projects_router, prefix=API_PREFIX)
app.include_router(targets_router, prefix=API_PREFIX)
app.include_router(stats_router, prefix=API_PREFIX)
app.include_router(audit_router, prefix=API_PREFIX)
app.include_router(pentest_router, prefix=API_PREFIX)
app.include_router(profiles_router, prefix=API_PREFIX)
app.include_router(diff_router, prefix=API_PREFIX)
app.include_router(ws_router)  # WebSocket at /ws (no version prefix)
app.include_router(c2_router, prefix=API_PREFIX)
app.include_router(cracking_router, prefix=API_PREFIX)
app.include_router(enrichment_router, prefix=API_PREFIX)
app.include_router(network_router, prefix=API_PREFIX)
app.include_router(osint_router, prefix=API_PREFIX)
app.include_router(credentials_router, prefix=API_PREFIX)
app.include_router(evidence_router, prefix=API_PREFIX)
app.include_router(ai_router, prefix=API_PREFIX)
app.include_router(auth_router, prefix=API_PREFIX)
app.include_router(passkeys_router, prefix=API_PREFIX)
app.include_router(playbooks_router, prefix=API_PREFIX)
app.include_router(vulns_router, prefix=API_PREFIX)
app.include_router(logs_router, prefix=API_PREFIX)
app.include_router(hardening_router, prefix=API_PREFIX)
app.include_router(demo_router, prefix=API_PREFIX)
app.include_router(notifications_router, prefix=API_PREFIX)
app.include_router(listeners_router, prefix=API_PREFIX)
app.include_router(agents_router, prefix=API_PREFIX)
app.include_router(webhooks_router, prefix=API_PREFIX)
app.include_router(attack_paths_router, prefix=API_PREFIX)
app.include_router(cve_watch_router, prefix=API_PREFIX)
app.include_router(attack_router, prefix=API_PREFIX)
app.include_router(ptes_router, prefix=API_PREFIX)
app.include_router(nessus_router, prefix=API_PREFIX)
app.include_router(hermes_router, prefix=API_PREFIX)
app.include_router(cloud_router, prefix=API_PREFIX)


# ── Settings / tools endpoint ─────────────────────────────────────────────────


@app.get(f"{API_PREFIX}/settings/tools")
def get_tool_status():
    """Re-detect all tools and return their status."""
    return detect_tools()


@app.get(f"{API_PREFIX}/settings/host-info")
def get_host_info():
    """Return OS type and package manager for the host running Seraph."""
    import platform as _platform
    import shutil as _shutil

    system = _platform.system().lower()  # "linux" | "darwin" | "windows"

    if system == "linux":
        os_release: dict[str, str] = {}
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    line = line.strip()
                    if "=" in line:
                        k, _, v = line.partition("=")
                        os_release[k] = v.strip('"')
        except FileNotFoundError:
            pass

        distro_id = os_release.get("ID", "").lower()
        id_like = os_release.get("ID_LIKE", "").lower()
        distro_name = os_release.get("PRETTY_NAME", distro_id or "Linux")

        # Detect package manager from distro identity
        if distro_id in ("ubuntu", "debian", "linuxmint", "kali", "parrot", "raspbian") or "debian" in id_like:
            pkg_manager = "apt"
        elif distro_id in ("fedora", "rhel", "centos", "almalinux", "rocky", "ol") or "fedora" in id_like or "rhel" in id_like:
            pkg_manager = "dnf" if _shutil.which("dnf") else "yum"
        elif distro_id in ("arch", "manjaro", "endeavouros", "garuda") or "arch" in id_like:
            pkg_manager = "pacman"
        elif distro_id == "alpine" or "alpine" in id_like:
            pkg_manager = "apk"
        elif distro_id in ("opensuse", "sles") or "suse" in id_like:
            pkg_manager = "zypper"
        else:
            # Fall back to which-detection
            for mgr in ("apt", "dnf", "yum", "pacman", "apk", "zypper"):
                if _shutil.which(mgr):
                    pkg_manager = mgr
                    break
            else:
                pkg_manager = "unknown"

        return {"os": "linux", "distro_id": distro_id, "distro_name": distro_name, "pkg_manager": pkg_manager}

    elif system == "darwin":
        return {"os": "macos", "distro_id": "macos", "distro_name": "macOS", "pkg_manager": "brew"}

    else:
        return {"os": system, "distro_id": system, "distro_name": system.title(), "pkg_manager": "unknown"}


@app.get(f"{API_PREFIX}/settings/auto-probe")
def get_auto_probe_settings(db=None):
    from database import get_db, AppSetting
    import json as _json
    db = next(get_db())
    try:
        def _get(key, default):
            row = db.query(AppSetting).filter(AppSetting.key == key).first()
            return row.value if row else default
        return {
            "enabled": _get("auto_probe_enabled", "false") == "true",
            "tools": _json.loads(_get("auto_probe_tools", '["whois","rustscan","nmap","nikto","testssl","nuclei","feroxbuster"]')),
            "intensity": _get("auto_probe_intensity", "standard"),
        }
    finally:
        db.close()


from pydantic import BaseModel as _BaseModel
class AutoProbeConfig(_BaseModel):
    enabled: bool
    tools: list[str]
    intensity: str = "standard"

@app.put(f"{API_PREFIX}/settings/auto-probe")
def save_auto_probe_settings(req: AutoProbeConfig):
    from database import get_db, AppSetting
    import json as _json
    db = next(get_db())
    try:
        def _set(key, value):
            row = db.query(AppSetting).filter(AppSetting.key == key).first()
            if row:
                row.value = value
            else:
                db.add(AppSetting(key=key, value=value))
        _set("auto_probe_enabled", "true" if req.enabled else "false")
        _set("auto_probe_tools", _json.dumps(req.tools))
        _set("auto_probe_intensity", req.intensity)
        db.commit()
        return {"ok": True}
    finally:
        db.close()


# ── Short agent install URL (/a/<code>) ───────────────────────────────────────

@app.get("/a/{short_code}", response_class=Response, include_in_schema=False)
async def short_agent_install(short_code: str, request: Request):
    """Short-form install script URL: curl -sSL http://HOST:8000/a/abc12345 | bash"""
    from database import get_db, Agent
    from routers.agents import get_install_script as _get_install_script
    db = next(get_db())
    try:
        agent = db.query(Agent).filter(Agent.short_code == short_code).first()
        if not agent:
            return Response(content="# Unknown short code\n", media_type="text/plain", status_code=404)
        return _get_install_script(agent.id, request, db)
    finally:
        db.close()


# ── Serve React frontend (SPA) ────────────────────────────────────────────────

FRONTEND_DIST = Path(__file__).parent.parent / "frontend" / "dist"

if FRONTEND_DIST.exists():
    # Mount static assets (JS, CSS, images etc.)
    app.mount(
        "/assets",
        StaticFiles(directory=str(FRONTEND_DIST / "assets")),
        name="assets",
    )

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(request: Request, full_path: str):
        """SPA fallback — serve index.html for all non-API routes."""
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail=f"API route not found: /{full_path}")
        index = FRONTEND_DIST / "index.html"
        if index.exists():
            return FileResponse(str(index))
        return {"detail": "Frontend not built. Run: npm run build in frontend/"}
else:
    @app.get("/", include_in_schema=False)
    async def root():
        return {
            "app": settings.app_name,
            "version": settings.version,
            "note": "Frontend not built. Run: npm run build in frontend/",
        }
