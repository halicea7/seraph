"""Hermes Agent integration — status, config, and run setup.

The actual execution + streaming happens over WS /ws/hermes/{scan_id} (routers/ws.py),
which reads the command prepared here. See services/hermes.py for the runner.
"""
import json
import uuid
from urllib.request import urlopen

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import Finding, Project, Scan, Target, get_db
from services import hermes as hsvc

router = APIRouter(prefix="/hermes", tags=["hermes"])


@router.get("/status")
def hermes_status(db: Session = Depends(get_db)):
    installed = hsvc.hermes_available()
    ollama_url = hsvc.get_setting(db, "ai_endpoint", "http://localhost:11434")
    ollama_reachable = False
    try:
        with urlopen(f"{ollama_url.rstrip('/')}/api/tags", timeout=3) as r:
            ollama_reachable = r.status == 200
    except Exception:
        ollama_reachable = False
    return {
        "installed": installed,
        "version": hsvc.hermes_version() if installed else "",
        "ollama_url": ollama_url,
        "ollama_reachable": ollama_reachable,
    }


class HermesConfigRequest(BaseModel):
    allow_private_urls: bool = True
    sandbox: bool = False
    default_model: str = ""


@router.get("/config")
def get_hermes_config(db: Session = Depends(get_db)):
    return {
        "allow_private_urls": hsvc.get_setting(db, "hermes_allow_private_urls", "true").lower() == "true",
        "sandbox": hsvc.get_setting(db, "hermes_sandbox", "false").lower() == "true",
        "default_model": hsvc.get_setting(db, "hermes_default_model", ""),
    }


@router.post("/config")
def save_hermes_config(req: HermesConfigRequest, db: Session = Depends(get_db)):
    hsvc.set_setting(db, "hermes_allow_private_urls", "true" if req.allow_private_urls else "false")
    hsvc.set_setting(db, "hermes_sandbox", "true" if req.sandbox else "false")
    hsvc.set_setting(db, "hermes_default_model", req.default_model)
    db.commit()
    return {"ok": True}


class HermesRunRequest(BaseModel):
    project_id: str
    target_id: str
    mode: str = "recon"
    model: str


@router.post("/run")
def create_hermes_run(req: HermesRunRequest, db: Session = Depends(get_db)):
    """Create a Scan record + prepare the Hermes command. Execution happens over WS."""
    if not hsvc.hermes_available():
        raise HTTPException(400, "Hermes is not installed on the Seraph host (pip install hermes-agent)")

    target = db.query(Target).filter(Target.id == req.target_id).first()
    if not target:
        raise HTTPException(404, "Target not found")
    project = db.query(Project).filter(Project.id == req.project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")

    # Project findings for engagement context.
    findings = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
        .filter(Target.project_id == req.project_id)
        .order_by(Finding.created_at.desc())
        .limit(40)
        .all()
    )

    scan_id = str(uuid.uuid4())
    prep = hsvc.prepare_run(db, scan_id, target, findings, req.mode, req.model)

    scan = Scan(
        id=scan_id,
        target_id=req.target_id,
        scan_type="hermes_operator",
        module="pentest",
        status="pending",
        config_json=json.dumps({
            "command": prep["command"],
            "mode": req.mode,
            "model": req.model,
            "engine": "hermes",
        }),
    )
    db.add(scan)
    db.commit()
    return {"scan_id": scan_id, "mode": req.mode, "model": req.model}
