import json
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import Playbook, PlaybookRun, Project, Target, get_db

router = APIRouter(prefix="/playbooks", tags=["playbooks"])


# ── Playbook CRUD ──────────────────────────────────────────────────────────────

@router.get("")
def list_playbooks(db: Session = Depends(get_db)):
    playbooks = db.query(Playbook).order_by(Playbook.is_builtin.desc(), Playbook.name).all()
    result = []
    for p in playbooks:
        try:
            steps = json.loads(p.steps_json)
        except Exception:
            steps = []
        result.append({
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "is_builtin": p.is_builtin,
            "step_count": len(steps),
            "steps": steps,
            "created_at": str(p.created_at),
        })
    return result


class CreatePlaybookRequest(BaseModel):
    name: str
    description: str = ""
    steps: list[dict]


@router.post("", status_code=201)
def create_playbook(req: CreatePlaybookRequest, db: Session = Depends(get_db)):
    pb = Playbook(
        id=str(uuid.uuid4()),
        name=req.name,
        description=req.description,
        steps_json=json.dumps(req.steps),
        is_builtin=False,
    )
    db.add(pb)
    db.commit()
    return {"id": pb.id, "name": pb.name}


class UpdatePlaybookRequest(BaseModel):
    name: str
    description: str = ""
    steps: list[dict]


@router.put("/{playbook_id}")
def update_playbook(playbook_id: str, req: UpdatePlaybookRequest,
                    db: Session = Depends(get_db)):
    pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not pb:
        raise HTTPException(404, "Playbook not found")
    if pb.is_builtin:
        raise HTTPException(400, "Cannot edit built-in playbooks")
    pb.name = req.name
    pb.description = req.description
    pb.steps_json = json.dumps(req.steps)
    db.commit()
    return {"id": pb.id, "name": pb.name}


@router.delete("/{playbook_id}")
def delete_playbook(playbook_id: str, db: Session = Depends(get_db)):
    pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not pb:
        raise HTTPException(404, "Playbook not found")
    if pb.is_builtin:
        raise HTTPException(400, "Cannot delete built-in playbooks")
    db.delete(pb)
    db.commit()
    return {"deleted": playbook_id}


# ── Runs ───────────────────────────────────────────────────────────────────────

class StartRunRequest(BaseModel):
    playbook_id: str
    project_id: str
    target_id: str
    mode: str = "auto"   # auto | step_through


@router.post("/runs", status_code=201)
def start_run(req: StartRunRequest, db: Session = Depends(get_db)):
    if not db.query(Playbook).filter(Playbook.id == req.playbook_id).first():
        raise HTTPException(404, "Playbook not found")
    if not db.query(Target).filter(Target.id == req.target_id).first():
        raise HTTPException(404, "Target not found")
    if req.mode not in ("auto", "step_through"):
        raise HTTPException(400, "mode must be 'auto' or 'step_through'")

    run = PlaybookRun(
        id=str(uuid.uuid4()),
        playbook_id=req.playbook_id,
        project_id=req.project_id,
        target_id=req.target_id,
        mode=req.mode,
        status="pending",
    )
    db.add(run)
    db.commit()
    return {"run_id": run.id, "mode": run.mode}


@router.get("/runs")
def list_runs(project_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(PlaybookRun)
    if project_id:
        query = query.filter(PlaybookRun.project_id == project_id)
    runs = query.order_by(PlaybookRun.created_at.desc()).limit(50).all()
    result = []
    for r in runs:
        pb = db.query(Playbook).filter(Playbook.id == r.playbook_id).first()
        target = db.query(Target).filter(Target.id == r.target_id).first()
        result.append({
            "id": r.id,
            "playbook_id": r.playbook_id,
            "playbook_name": pb.name if pb else "Unknown",
            "project_id": r.project_id,
            "target_id": r.target_id,
            "target_host": target.hostname_or_ip if target else "unknown",
            "mode": r.mode,
            "status": r.status,
            "current_step": r.current_step,
            "started_at": str(r.started_at) if r.started_at else None,
            "completed_at": str(r.completed_at) if r.completed_at else None,
            "created_at": str(r.created_at),
        })
    return result


@router.get("/runs/{run_id}")
def get_run(run_id: str, db: Session = Depends(get_db)):
    run = db.query(PlaybookRun).filter(PlaybookRun.id == run_id).first()
    if not run:
        raise HTTPException(404, "Run not found")
    pb = db.query(Playbook).filter(Playbook.id == run.playbook_id).first()
    target = db.query(Target).filter(Target.id == run.target_id).first()
    try:
        results = json.loads(run.results_json or "{}")
    except Exception:
        results = {}
    return {
        "id": run.id,
        "playbook_id": run.playbook_id,
        "playbook_name": pb.name if pb else "Unknown",
        "target_host": target.hostname_or_ip if target else "unknown",
        "mode": run.mode,
        "status": run.status,
        "current_step": run.current_step,
        "results": results,
        "started_at": str(run.started_at) if run.started_at else None,
        "completed_at": str(run.completed_at) if run.completed_at else None,
    }
