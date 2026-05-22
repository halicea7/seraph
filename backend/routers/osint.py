import importlib.util
import json
import re
import shutil

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from database import Scan, SherlockJob, get_db
from services.validators import validate_domain, validate_pentest_command

router = APIRouter(prefix="/osint", tags=["osint"])

OSINT_TOOLS = {
    "theHarvester": {
        "tool": "theHarvester",
        "description": "Gather emails, subdomains, and hosts from public sources (certs, search engines, DNS).",
        "command_template": "theHarvester -d {domain} -b all -l 200",
        "install": "pip install theHarvester",
    },
    "amass": {
        "tool": "amass",
        "description": "In-depth passive subdomain enumeration across 50+ data sources.",
        "command_template": "amass enum -passive -d {domain}",
        "install": "apt install amass",
    },
    "subfinder": {
        "tool": "subfinder",
        "description": "Fast passive subdomain discovery using 40+ passive sources.",
        "command_template": "subfinder -d {domain}",
        "install": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    },
}


@router.get("/tools")
def get_osint_tools():
    return {
        key: {**tool, "available": shutil.which(tool["tool"]) is not None}
        for key, tool in OSINT_TOOLS.items()
    }


class OSINTRunRequest(BaseModel):
    project_id: str
    target_id: str
    domain: str
    tool_name: str
    command: str

    @field_validator("domain")
    @classmethod
    def _check_domain(cls, v: str) -> str:
        return validate_domain(v)

    @field_validator("tool_name")
    @classmethod
    def _check_tool_name(cls, v: str) -> str:
        if v not in OSINT_TOOLS:
            raise ValueError(f"Unknown OSINT tool: {v!r}")
        return v

    @field_validator("command")
    @classmethod
    def _check_command(cls, v: str) -> str:
        return validate_pentest_command(v)


# ── Sherlock ──────────────────────────────────────────────────────────────────

def _sherlock_command(username: str) -> str | None:
    if shutil.which("sherlock"):
        return f"sherlock {username} --no-color"
    if importlib.util.find_spec("sherlock_project"):
        return f"python3 -m sherlock_project {username} --no-color"
    return None


@router.get("/sherlock/status")
def sherlock_status():
    available = bool(shutil.which("sherlock")) or bool(importlib.util.find_spec("sherlock_project"))
    return {"available": available}


class SherlockRunRequest(BaseModel):
    project_id: str
    username: str

    @field_validator("username")
    @classmethod
    def _check_username(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r'^[a-zA-Z0-9._-]{1,50}$', v):
            raise ValueError("Username must be 1–50 alphanumeric/._- characters")
        return v


@router.post("/sherlock/run")
def run_sherlock(req: SherlockRunRequest, db: Session = Depends(get_db)):
    command = _sherlock_command(req.username)
    if not command:
        raise HTTPException(503, "Sherlock is not installed. Run: pip install sherlock-project")

    job = SherlockJob(
        project_id=req.project_id or None,
        username=req.username,
        command=command,
        status="pending",
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return {"job_id": job.id}


# ── Domain OSINT ──────────────────────────────────────────────────────────────

@router.post("/run")
def run_osint(req: OSINTRunRequest, db: Session = Depends(get_db)):
    if req.tool_name not in OSINT_TOOLS:
        raise HTTPException(400, f"Unknown OSINT tool: {req.tool_name}")

    scan = Scan(
        target_id=req.target_id,
        scan_type=f"osint_{req.tool_name}",
        module="pentest",
        status="pending",
        config_json=json.dumps({
            "command": req.command,
            "tool": req.tool_name,
            "domain": req.domain,
            "project_id": req.project_id,
            "target_id": req.target_id,
        }),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return {"scan_id": scan.id}
