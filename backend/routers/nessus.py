"""Nessus / Tenable.io integration — connect, launch & control scans, import
findings, and export reports. The HTTP client and import logic live in
services/nessus.py (shared with the background poller in services/scheduler.py).
"""
import json
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import Project, Scan, Target, get_db
from services.vault import encrypt
from services.nessus import (
    _TENABLE_HOST,
    get_setting,
    set_setting,
    load_client,
    import_scan_results,
)

router = APIRouter(prefix="/nessus", tags=["nessus"])


# ── Status & config ───────────────────────────────────────────────────────────

@router.get("/status")
def nessus_status(db: Session = Depends(get_db)):
    configured = bool(get_setting(db, "nessus_host"))
    if not configured:
        return {"configured": False, "connected": False, "error": "Not configured"}
    try:
        client = load_client(db)
        client.authenticate()
        client.get("/server/status")
        return {"configured": True, "connected": True, "error": None}
    except HTTPException as e:
        return {"configured": True, "connected": False, "error": e.detail}
    except Exception as e:
        return {"configured": True, "connected": False, "error": str(e)}


class NessusConfigRequest(BaseModel):
    host: str
    port: int = 8834
    username: str = ""
    password: str = ""
    verify_ssl: bool = False
    api_access_key: str = ""
    api_secret_key: str = ""


@router.post("/config")
def save_nessus_config(req: NessusConfigRequest, db: Session = Depends(get_db)):
    auth_type = "apikey" if req.host.strip().rstrip("/") == _TENABLE_HOST else "session"
    set_setting(db, "nessus_host", req.host.strip().rstrip("/"))
    set_setting(db, "nessus_port", str(req.port))
    set_setting(db, "nessus_username", req.username)
    set_setting(db, "nessus_verify_ssl", "true" if req.verify_ssl else "false")
    set_setting(db, "nessus_auth_type", auth_type)
    if req.password:
        set_setting(db, "nessus_password", encrypt(req.password))
    if req.api_access_key:
        set_setting(db, "nessus_api_access_key", encrypt(req.api_access_key))
    if req.api_secret_key:
        set_setting(db, "nessus_api_secret_key", encrypt(req.api_secret_key))
    db.commit()
    return {"ok": True, "auth_type": auth_type}


@router.get("/config")
def get_nessus_config(db: Session = Depends(get_db)):
    return {
        "host": get_setting(db, "nessus_host"),
        "port": int(get_setting(db, "nessus_port", "8834")),
        "username": get_setting(db, "nessus_username"),
        "auth_type": get_setting(db, "nessus_auth_type", "session"),
        "verify_ssl": get_setting(db, "nessus_verify_ssl", "false") == "true",
    }


# ── Templates / policies / folders (for the launch UI) ────────────────────────

@router.get("/templates")
def list_templates(db: Session = Depends(get_db)):
    client = load_client(db)
    try:
        data = client.get("/editor/scan/templates")
    except Exception as e:
        raise HTTPException(502, f"Nessus error: {e}")
    return [
        {
            "uuid": t.get("uuid"),
            "name": t.get("name", ""),
            "title": t.get("title", ""),
            "description": t.get("description", ""),
            "is_agent": t.get("is_agent", False),
        }
        for t in (data.get("templates") or [])
    ]


@router.get("/policies")
def list_policies(db: Session = Depends(get_db)):
    client = load_client(db)
    try:
        data = client.get("/policies")
    except Exception as e:
        raise HTTPException(502, f"Nessus error: {e}")
    return [
        {"id": p.get("id"), "name": p.get("name", ""), "description": p.get("description", "")}
        for p in (data.get("policies") or [])
    ]


@router.get("/folders")
def list_folders(db: Session = Depends(get_db)):
    client = load_client(db)
    try:
        data = client.get("/folders")
    except Exception as e:
        raise HTTPException(502, f"Nessus error: {e}")
    return [
        {"id": f.get("id"), "name": f.get("name", ""), "type": f.get("type", "")}
        for f in (data.get("folders") or [])
    ]


# ── Scan listing & detail ─────────────────────────────────────────────────────

@router.get("/scans")
def list_nessus_scans(db: Session = Depends(get_db)):
    client = load_client(db)
    try:
        client.authenticate()
        data = client.get("/scans")
    except Exception as e:
        raise HTTPException(502, f"Nessus error: {e}")
    scans = data.get("scans") or []
    return [
        {
            "id": s.get("id"),
            "name": s.get("name", ""),
            "status": s.get("status", ""),
            "last_modification_date": s.get("last_modification_date"),
            "host_count": s.get("hosts_total", 0),
        }
        for s in scans
    ]


@router.get("/scans/{nessus_scan_id}")
def get_nessus_scan(nessus_scan_id: int, db: Session = Depends(get_db)):
    client = load_client(db)
    try:
        client.authenticate()
        data = client.get(f"/scans/{nessus_scan_id}")
    except Exception as e:
        raise HTTPException(502, f"Nessus error: {e}")
    info = data.get("info", {})
    hosts = [
        {"host_id": h.get("host_id"), "hostname": h.get("hostname", ""),
         "critical": h.get("critical", 0), "high": h.get("high", 0),
         "medium": h.get("medium", 0), "low": h.get("low", 0), "info": h.get("info", 0)}
        for h in (data.get("hosts") or [])
    ]
    return {
        "id": nessus_scan_id,
        "name": info.get("name", ""),
        "status": info.get("status", ""),
        "progress": info.get("progress", 0),
        "hosts": hosts,
    }


# ── Launch & control ──────────────────────────────────────────────────────────

class NessusLaunchRequest(BaseModel):
    project_id: str
    template_uuid: str
    policy_id: int | None = None
    folder_id: int | None = None
    name: str = ""
    targets: str = ""


@router.post("/scans/launch")
def launch_nessus_scan(req: NessusLaunchRequest, db: Session = Depends(get_db)):
    """Create a scan in Nessus from a template (+optional policy), launch it, and
    create a job-tracker Seraph Scan the poller will follow to completion."""
    project = db.query(Project).filter(Project.id == req.project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")
    if not req.targets.strip():
        raise HTTPException(400, "Provide one or more targets")

    name = req.name.strip() or f"Seraph scan {datetime.utcnow():%Y-%m-%d %H:%M}"
    settings: dict = {"name": name, "text_targets": req.targets.strip()}
    if req.policy_id is not None:
        settings["policy_id"] = req.policy_id
    if req.folder_id is not None:
        settings["folder_id"] = req.folder_id

    client = load_client(db)
    try:
        created = client.post("/scans", {"uuid": req.template_uuid, "settings": settings})
        nessus_scan_id = created.get("scan", {}).get("id")
        if not nessus_scan_id:
            raise HTTPException(502, "Nessus did not return a scan id")
        client.post(f"/scans/{nessus_scan_id}/launch")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"Nessus error: {e}")

    # Job-tracker target + scan (poller fans out per-host results on completion).
    target = Target(
        id=str(uuid.uuid4()),
        project_id=req.project_id,
        hostname_or_ip=name,
        target_type="network",
        notes=f"Nessus scan job · targets: {req.targets.strip()[:200]}",
    )
    db.add(target)
    db.flush()

    scan = Scan(
        id=str(uuid.uuid4()),
        target_id=target.id,
        scan_type="nessus_job",
        module="pentest",
        status="running",
        config_json=json.dumps({"nessus_scan_id": nessus_scan_id, "scan_name": name,
                                 "targets": req.targets.strip()}),
        started_at=datetime.utcnow(),
        nessus_scan_id=nessus_scan_id,
        nessus_status="running",
        nessus_progress=0,
    )
    db.add(scan)
    db.commit()
    return {"scan_id": scan.id, "nessus_scan_id": nessus_scan_id, "name": name}


_CONTROL_ACTIONS = {"pause", "resume", "stop", "kill"}


@router.post("/scans/{nessus_scan_id}/control/{action}")
def control_nessus_scan(nessus_scan_id: int, action: str, db: Session = Depends(get_db)):
    if action not in _CONTROL_ACTIONS:
        raise HTTPException(400, f"Unknown action '{action}'")
    client = load_client(db)
    try:
        client.post(f"/scans/{nessus_scan_id}/{action}")
    except Exception as e:
        raise HTTPException(502, f"Nessus error: {e}")

    # Reflect optimistic state on the tracker.
    tracker = db.query(Scan).filter(Scan.nessus_scan_id == nessus_scan_id,
                                    Scan.scan_type == "nessus_job").first()
    if tracker:
        tracker.nessus_status = {"pause": "paused", "resume": "running",
                                 "stop": "stopping", "kill": "stopping"}.get(action, action)
        if action in ("stop", "kill"):
            tracker.status = "failed" if action == "kill" else tracker.status
        db.commit()
    return {"ok": True, "action": action}


# ── Manual import (existing scans) ────────────────────────────────────────────

class NessusImportRequest(BaseModel):
    project_id: str = ""
    project_name: str = ""
    host_ids: list[int] = []


@router.post("/scans/{nessus_scan_id}/import")
def import_nessus_scan(nessus_scan_id: int, req: NessusImportRequest, db: Session = Depends(get_db)):
    if req.project_id:
        project = db.query(Project).filter(Project.id == req.project_id).first()
        if not project:
            raise HTTPException(404, "Project not found")
        project_id = req.project_id
    elif req.project_name.strip():
        project = Project(id=str(uuid.uuid4()), name=req.project_name.strip(),
                          description="Imported from Nessus")
        db.add(project)
        db.flush()
        project_id = project.id
    else:
        raise HTTPException(400, "Provide either project_id or project_name")

    client = load_client(db)
    try:
        client.authenticate()
        result = import_scan_results(db, client, nessus_scan_id, project_id,
                                     req.host_ids or None)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"Nessus error: {e}")
    return result


# ── Report export ─────────────────────────────────────────────────────────────

_EXPORT_FORMATS = {"nessus", "pdf", "html", "csv"}


class NessusExportRequest(BaseModel):
    format: str = "pdf"


@router.post("/scans/{nessus_scan_id}/export")
def request_export(nessus_scan_id: int, req: NessusExportRequest, db: Session = Depends(get_db)):
    fmt = req.format.lower()
    if fmt not in _EXPORT_FORMATS:
        raise HTTPException(400, f"Unsupported format '{req.format}'")
    client = load_client(db)
    try:
        resp = client.post(f"/scans/{nessus_scan_id}/export", {"format": fmt})
    except Exception as e:
        raise HTTPException(502, f"Nessus error: {e}")
    file_id = resp.get("file") or resp.get("file_id")
    if not file_id:
        raise HTTPException(502, "Nessus did not return an export file id")

    tracker = db.query(Scan).filter(Scan.nessus_scan_id == nessus_scan_id,
                                    Scan.scan_type == "nessus_job").first()
    export = {"format": fmt, "file_id": file_id, "state": "pending", "report_id": None}
    if tracker:
        tracker.nessus_export_json = json.dumps(export)
        db.commit()
    return {"ok": True, "file_id": file_id, "format": fmt}


@router.get("/scans/{nessus_scan_id}/export/{file_id}/status")
def export_status(nessus_scan_id: int, file_id: int, db: Session = Depends(get_db)):
    client = load_client(db)
    try:
        data = client.get(f"/scans/{nessus_scan_id}/export/{file_id}/status")
    except Exception as e:
        raise HTTPException(502, f"Nessus error: {e}")
    return {"status": data.get("status", "")}


@router.get("/scans/{nessus_scan_id}/export/{file_id}/download")
def download_export(nessus_scan_id: int, file_id: int, db: Session = Depends(get_db)):
    client = load_client(db)
    try:
        status = client.get(f"/scans/{nessus_scan_id}/export/{file_id}/status").get("status", "")
        if status != "ready":
            raise HTTPException(409, f"Export not ready (status: {status or 'unknown'})")
        content = client.download(f"/scans/{nessus_scan_id}/export/{file_id}/download")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"Nessus error: {e}")

    ext_ctype = {
        "nessus": ("nessus", "application/xml"),
        "pdf": ("pdf", "application/pdf"),
        "html": ("html", "text/html"),
        "csv": ("csv", "text/csv"),
    }
    # Infer extension from the tracker's recorded export, default to bin.
    tracker = db.query(Scan).filter(Scan.nessus_scan_id == nessus_scan_id,
                                    Scan.scan_type == "nessus_job").first()
    fmt = "pdf"
    if tracker and tracker.nessus_export_json:
        try:
            fmt = json.loads(tracker.nessus_export_json).get("format", "pdf")
        except Exception:
            pass
    ext, ctype = ext_ctype.get(fmt, ("bin", "application/octet-stream"))
    filename = f"nessus_scan_{nessus_scan_id}.{ext}"
    return Response(content=content, media_type=ctype,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})
