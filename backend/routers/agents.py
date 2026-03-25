"""
Agent router — lightweight defensive audit agents that phone home for jobs.
"""

import uuid
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import Agent, AgentJob, Finding, Notification, Scan, Target, get_db

router = APIRouter(prefix="/agents", tags=["agents"])

# ── Pydantic models ────────────────────────────────────────────────────────────


class AgentCreate(BaseModel):
    name: str
    target_id: Optional[str] = None


class JobCreate(BaseModel):
    categories: list[str]


class JobResult(BaseModel):
    output: str
    exit_code: int


# ── Helpers ────────────────────────────────────────────────────────────────────

OFFLINE_THRESHOLD = 90  # seconds


def _mark_offline(db: Session, agents: list[Agent]) -> None:
    cutoff = datetime.utcnow() - timedelta(seconds=OFFLINE_THRESHOLD)
    changed = False
    for agent in agents:
        if agent.status == "online" and (agent.last_seen is None or agent.last_seen < cutoff):
            agent.status = "offline"
            changed = True
    if changed:
        db.commit()


def _agent_dict(agent: Agent, db: Session) -> dict:
    target = db.query(Target).filter(Target.id == agent.target_id).first() if agent.target_id else None
    return {
        "id": agent.id,
        "name": agent.name,
        "target_id": agent.target_id,
        "target_hostname": target.hostname_or_ip if target else None,
        "token": agent.token,
        "hostname": agent.hostname,
        "platform": agent.platform,
        "status": agent.status,
        "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
        "created_at": agent.created_at.isoformat() if agent.created_at else None,
    }


def _job_dict(job: AgentJob) -> dict:
    return {
        "id": job.id,
        "agent_id": job.agent_id,
        "scan_id": job.scan_id,
        "categories": job.categories,
        "status": job.status,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        "exit_code": job.exit_code,
        "output": job.output,
    }


# ── Agent poll / result (defined before /{agent_id} to avoid wildcard capture) ─


@router.get("/poll/{token}")
def agent_poll(
    token: str,
    hostname: Optional[str] = Query(None),
    platform: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """Agent checks in and receives pending jobs."""
    agent = db.query(Agent).filter(Agent.token == token).first()
    if not agent:
        raise HTTPException(404, "Unknown token")

    now = datetime.utcnow()
    agent.status = "online"
    agent.last_seen = now
    if hostname:
        agent.hostname = hostname
    if platform:
        agent.platform = platform

    # Fetch pending jobs
    pending = (
        db.query(AgentJob)
        .filter(AgentJob.agent_id == agent.id, AgentJob.status == "pending")
        .order_by(AgentJob.created_at)
        .all()
    )

    # Mark them as running
    for job in pending:
        job.status = "running"
        job.started_at = now

    db.commit()

    return [{"id": j.id, "script": j.script} for j in pending]


@router.post("/result/{token}/{job_id}")
def agent_result(token: str, job_id: str, body: JobResult, db: Session = Depends(get_db)):
    """Agent posts job output."""
    from services.output_parser import auto_parse_scan_output

    agent = db.query(Agent).filter(Agent.token == token).first()
    if not agent:
        raise HTTPException(404, "Unknown token")

    job = (
        db.query(AgentJob)
        .filter(AgentJob.id == job_id, AgentJob.agent_id == agent.id)
        .first()
    )
    if not job:
        raise HTTPException(404, "Job not found")

    now = datetime.utcnow()
    job.output = body.output
    job.exit_code = body.exit_code
    job.completed_at = now
    job.status = "completed" if body.exit_code == 0 else "failed"

    # Update linked Scan record if present
    if job.scan_id:
        scan = db.query(Scan).filter(Scan.id == job.scan_id).first()
        if scan:
            scan.raw_output = body.output
            scan.completed_at = now
            scan.status = "completed" if body.exit_code == 0 else "failed"
            if not scan.started_at:
                scan.started_at = job.started_at or now
            db.flush()

            # Auto-parse findings
            if body.exit_code == 0 and scan.raw_output:
                parsed = auto_parse_scan_output(scan.scan_type, scan.raw_output)
                for pf in parsed:
                    db.add(Finding(
                        id=str(uuid.uuid4()),
                        scan_id=scan.id,
                        severity=pf.severity,
                        title=pf.title,
                        description=pf.description or "",
                        control_id=pf.control_id,
                        framework=pf.framework,
                        remediation=pf.remediation,
                        evidence=pf.evidence,
                        status="open",
                    ))
                if parsed:
                    highs = sum(1 for p in parsed if p.severity in ("critical", "high"))
                    db.add(Notification(
                        title=f"Agent job complete — {len(parsed)} finding(s)",
                        body=f"Agent '{agent.name}': {len(parsed)} finding(s) parsed" + (f", {highs} critical/high" if highs else ""),
                        type="critical" if highs > 0 else "info",
                        scan_id=job.scan_id,
                    ))

    db.commit()
    return {"ok": True}


# ── Agent CRUD ─────────────────────────────────────────────────────────────────


@router.post("")
def create_agent(body: AgentCreate, db: Session = Depends(get_db)):
    if body.target_id:
        target = db.query(Target).filter(Target.id == body.target_id).first()
        if not target:
            raise HTTPException(404, "Target not found")

    agent = Agent(
        name=body.name,
        target_id=body.target_id or None,
        token=str(uuid.uuid4()),
        status="offline",
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return _agent_dict(agent, db)


@router.get("")
def list_agents(
    project_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(Agent)
    if project_id:
        # Filter agents whose target belongs to the project
        target_ids = [t.id for t in db.query(Target).filter(Target.project_id == project_id).all()]
        q = q.filter(Agent.target_id.in_(target_ids))
    agents = q.all()
    _mark_offline(db, agents)
    return [_agent_dict(a, db) for a in agents]


@router.delete("/{agent_id}", status_code=204)
def delete_agent(agent_id: str, db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(404, "Agent not found")
    db.delete(agent)
    db.commit()


# ── Install script ─────────────────────────────────────────────────────────────


@router.get("/{agent_id}/install-script", response_class=PlainTextResponse)
def get_install_script(agent_id: str, request: Request, db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(404, "Agent not found")

    base_url = str(request.base_url).rstrip("/")
    token = agent.token

    # The embedded agent.py content (runs as a systemd service)
    agent_py = f'''#!/usr/bin/env python3
"""Seraph defensive audit agent."""
import subprocess
import time
import socket
import platform
import sys

try:
    import requests
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "requests", "-q"], check=True)
    import requests

SERAPH_URL = "{base_url}"
TOKEN = "{token}"
POLL_URL = f"{{SERAPH_URL}}/api/v1/agents/poll/{{TOKEN}}"
RESULT_URL = f"{{SERAPH_URL}}/api/v1/agents/result/{{TOKEN}}"
POLL_INTERVAL = 60  # seconds

def get_info():
    return {{
        "hostname": socket.gethostname(),
        "platform": platform.system().lower(),
    }}

def run_job(job):
    job_id = job["id"]
    script = job["script"]
    print(f"[seraph-agent] Running job {{job_id}}", flush=True)
    result = subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
    )
    output = result.stdout + result.stderr
    exit_code = result.returncode
    print(f"[seraph-agent] Job {{job_id}} finished with exit_code={{exit_code}}", flush=True)
    try:
        requests.post(
            f"{{RESULT_URL}}/{{job_id}}",
            json={{"output": output, "exit_code": exit_code}},
            timeout=30,
        )
    except Exception as e:
        print(f"[seraph-agent] Failed to post result for {{job_id}}: {{e}}", flush=True)

def main():
    info = get_info()
    print(f"[seraph-agent] Starting. Hostname={{info['hostname']}} Platform={{info['platform']}}", flush=True)
    while True:
        try:
            resp = requests.get(
                POLL_URL,
                params=info,
                timeout=15,
            )
            if resp.status_code == 200:
                jobs = resp.json()
                for job in jobs:
                    run_job(job)
            else:
                print(f"[seraph-agent] Poll returned HTTP {{resp.status_code}}", flush=True)
        except Exception as e:
            print(f"[seraph-agent] Poll error: {{e}}", flush=True)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
'''

    # Bash install script embedding agent.py via heredoc
    bash_script = f'''#!/usr/bin/env bash
# Seraph Agent Installer
# Agent: {agent.name}
set -e

echo "[seraph] Installing Seraph audit agent..."

# Install python3 and requests if needed
if ! command -v python3 &>/dev/null; then
    echo "[seraph] Installing python3..."
    apt-get update -qq && apt-get install -y -qq python3 python3-pip
elif ! python3 -c "import requests" &>/dev/null; then
    echo "[seraph] Installing python3-requests..."
    apt-get update -qq && apt-get install -y -qq python3-requests 2>/dev/null || pip3 install requests -q
fi

# Create agent directory
mkdir -p /opt/seraph-agent

# Write agent.py
cat > /opt/seraph-agent/agent.py << 'SERAPH_AGENT_EOF'
{agent_py}
SERAPH_AGENT_EOF

chmod +x /opt/seraph-agent/agent.py

# Install systemd service
cat > /etc/systemd/system/seraph-agent.service << 'SERAPH_SERVICE_EOF'
[Unit]
Description=Seraph Defensive Audit Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/seraph-agent/agent.py
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERAPH_SERVICE_EOF

systemctl daemon-reload
systemctl enable seraph-agent
systemctl restart seraph-agent

echo "[seraph] Agent installed and started."
echo "[seraph] Check status: systemctl status seraph-agent"
echo "[seraph] View logs:    journalctl -u seraph-agent -f"
'''

    return PlainTextResponse(
        content=bash_script,
        media_type="text/x-shellscript",
        headers={"Content-Disposition": f'attachment; filename="seraph-agent-install-{agent_id[:8]}.sh"'},
    )


# ── Manual jobs ────────────────────────────────────────────────────────────────


@router.post("/{agent_id}/jobs")
def push_job(agent_id: str, body: JobCreate, db: Session = Depends(get_db)):
    from services.script_generator import generate_script

    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(404, "Agent not found")

    if not body.categories:
        raise HTTPException(400, "At least one category required")

    scan_categories = [{"category_id": c} for c in body.categories]
    script = generate_script(
        project_name="agent",
        target="localhost",
        scan_categories=scan_categories,
    )

    # Create a Scan record if agent has a target
    scan_id = None
    if agent.target_id:
        scan = Scan(
            target_id=agent.target_id,
            scan_type=",".join(body.categories),
            module="audit",
            status="pending",
            created_at=datetime.utcnow(),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id

    job = AgentJob(
        agent_id=agent_id,
        scan_id=scan_id,
        categories=",".join(body.categories),
        script=script,
        status="pending",
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return _job_dict(job)


@router.get("/{agent_id}/jobs")
def list_jobs(agent_id: str, db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(404, "Agent not found")

    jobs = (
        db.query(AgentJob)
        .filter(AgentJob.agent_id == agent_id)
        .order_by(AgentJob.created_at.desc())
        .limit(50)
        .all()
    )
    return [_job_dict(j) for j in jobs]
