"""
Web Screenshot Gallery.

Capture screenshots of discovered web hosts with gowitness and serve them back as
a visual triage gallery. Capture runs stream over /ws/screenshots/{job_id}; the
images are indexed into Screenshot rows on completion.
"""

import os
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db, Project, Screenshot
from services.scope_service import check_scope
from services.screenshot import create_job

router = APIRouter(prefix="/screenshots", tags=["screenshots"])


class RunRequest(BaseModel):
    project_id: str
    target_id: str | None = None
    urls: list[str]


def _host(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.hostname or url


@router.post("/run")
def run_capture(req: RunRequest, db: Session = Depends(get_db)):
    """Start a screenshot job. Out-of-scope URLs are dropped before launch."""
    project = db.query(Project).filter(Project.id == req.project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")

    in_scope, skipped = [], []
    for url in req.urls:
        ok, _ = check_scope(_host(url), project.scope_json)
        (in_scope if ok else skipped).append(url)

    if not in_scope:
        raise HTTPException(400, "All URLs are out of scope for this project")

    try:
        job = create_job(req.project_id, req.target_id, in_scope)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    return {"job_id": job["job_id"], "captured_urls": len(in_scope), "skipped": skipped}


def _row(s: Screenshot) -> dict:
    return {
        "id": s.id,
        "project_id": s.project_id,
        "target_id": s.target_id,
        "url": s.url,
        "title": s.title,
        "status_code": s.status_code,
        "finding_id": s.finding_id,
        "captured_at": s.captured_at.isoformat() if s.captured_at else None,
    }


@router.get("")
def list_screenshots(
    project_id: str | None = Query(None),
    finding_id: str | None = Query(None),
    db: Session = Depends(get_db),
):
    if not project_id and not finding_id:
        raise HTTPException(400, "project_id or finding_id required")
    q = db.query(Screenshot)
    if project_id:
        q = q.filter(Screenshot.project_id == project_id)
    if finding_id:
        q = q.filter(Screenshot.finding_id == finding_id)
    return [_row(s) for s in q.order_by(Screenshot.captured_at.desc()).all()]


class LinkRequest(BaseModel):
    finding_id: str | None = None  # null to unlink


@router.post("/{shot_id}/link")
def link_screenshot(shot_id: str, req: LinkRequest, db: Session = Depends(get_db)):
    """Attach (or detach, with finding_id=null) a screenshot as evidence for a finding."""
    s = db.query(Screenshot).filter(Screenshot.id == shot_id).first()
    if not s:
        raise HTTPException(404, "Screenshot not found")
    if req.finding_id:
        from database import Finding
        if not db.query(Finding).filter(Finding.id == req.finding_id).first():
            raise HTTPException(404, "Finding not found")
    s.finding_id = req.finding_id
    db.commit()
    return _row(s)


@router.get("/{shot_id}/image")
def get_image(shot_id: str, db: Session = Depends(get_db)):
    s = db.query(Screenshot).filter(Screenshot.id == shot_id).first()
    if not s or not s.image_path or not os.path.exists(s.image_path):
        raise HTTPException(404, "Screenshot image not found")
    return FileResponse(s.image_path)


@router.delete("/{shot_id}")
def delete_screenshot(shot_id: str, db: Session = Depends(get_db)):
    s = db.query(Screenshot).filter(Screenshot.id == shot_id).first()
    if not s:
        raise HTTPException(404, "Screenshot not found")
    # Best-effort remove the file too.
    try:
        if s.image_path and os.path.exists(s.image_path):
            os.remove(s.image_path)
    except OSError:
        pass
    db.delete(s)
    db.commit()
    return {"ok": True}
