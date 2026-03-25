import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
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
from routers.playbooks import router as playbooks_router
from routers.vulns import router as vulns_router
from routers.logs import router as logs_router
from routers.hardening import router as hardening_router
from routers.demo import router as demo_router
from routers.notifications import router as notifications_router
from routers.listeners import router as listeners_router
from routers.agents import router as agents_router
from services.tool_registry import detect_tools, initialize_registry
from services.scheduler import initialize_scheduler
from services.playbook_runner import seed_builtin_playbooks
from services.listener_manager import initialize_listeners


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
    yield
    # Shutdown (nothing to clean up)


app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    lifespan=lifespan,
)

# CORS — allow all origins for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
app.include_router(playbooks_router, prefix=API_PREFIX)
app.include_router(vulns_router, prefix=API_PREFIX)
app.include_router(logs_router, prefix=API_PREFIX)
app.include_router(hardening_router, prefix=API_PREFIX)
app.include_router(demo_router, prefix=API_PREFIX)
app.include_router(notifications_router, prefix=API_PREFIX)
app.include_router(listeners_router, prefix=API_PREFIX)
app.include_router(agents_router, prefix=API_PREFIX)


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
            "tools": _json.loads(_get("auto_probe_tools", '["whois","nmap","nikto","testssl"]')),
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
