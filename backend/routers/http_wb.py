"""
HTTP Request Workbench.

Repeater/Intruder-lite: send/replay a single HTTP request, fuzz a §FUZZ§ marker
across payloads (streamed over /ws/httpfuzz/{run_id}), and persist a per-project
request collection. Scope is enforced on the request host before anything is sent.
"""

import json
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db, Project, HttpRequestItem
from services.scope_service import check_scope
from services.http_workbench import send_request, create_fuzz_job

router = APIRouter(prefix="/http", tags=["http-workbench"])


def _host(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.hostname or url


def _enforce_scope(db: Session, project_id: str, url: str) -> None:
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")
    ok, reason = check_scope(_host(url), project.scope_json)
    if not ok:
        raise HTTPException(403, f"Target out of scope: {reason}")


# ── Send ──────────────────────────────────────────────────────────────────────

class SendRequest(BaseModel):
    project_id: str
    method: str = "GET"
    url: str
    headers: dict[str, str] = {}
    body: str = ""


@router.post("/send")
async def http_send(req: SendRequest, db: Session = Depends(get_db)):
    _enforce_scope(db, req.project_id, req.url)
    try:
        return await send_request(req.method, req.url, req.headers, req.body)
    except Exception as exc:
        raise HTTPException(502, f"Request failed: {exc}")


# ── Fuzz (creates a streaming job) ────────────────────────────────────────────

class FuzzRequest(BaseModel):
    project_id: str
    method: str = "GET"
    url: str
    headers: dict[str, str] = {}
    body: str = ""
    payloads: list[str] = []


@router.post("/fuzz")
def http_fuzz(req: FuzzRequest, db: Session = Depends(get_db)):
    _enforce_scope(db, req.project_id, req.url)
    try:
        return create_fuzz_job(req.method, req.url, req.headers, req.body, req.payloads)
    except ValueError as exc:
        raise HTTPException(400, str(exc))


# ── Saved request collection ──────────────────────────────────────────────────

class SaveRequest(BaseModel):
    project_id: str
    name: str = ""
    method: str = "GET"
    url: str
    headers: dict[str, str] = {}
    body: str = ""


def _item(r: HttpRequestItem) -> dict:
    return {
        "id": r.id,
        "project_id": r.project_id,
        "name": r.name,
        "method": r.method,
        "url": r.url,
        "headers": json.loads(r.headers_json or "{}"),
        "body": r.body,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


@router.get("/requests")
def list_requests(project_id: str = Query(...), db: Session = Depends(get_db)):
    rows = (
        db.query(HttpRequestItem)
        .filter(HttpRequestItem.project_id == project_id)
        .order_by(HttpRequestItem.created_at.desc())
        .all()
    )
    return [_item(r) for r in rows]


@router.post("/requests")
def save_request(req: SaveRequest, db: Session = Depends(get_db)):
    item = HttpRequestItem(
        project_id=req.project_id,
        name=req.name or req.url,
        method=req.method,
        url=req.url,
        headers_json=json.dumps(req.headers),
        body=req.body,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return _item(item)


@router.delete("/requests/{request_id}")
def delete_request(request_id: str, db: Session = Depends(get_db)):
    item = db.query(HttpRequestItem).filter(HttpRequestItem.id == request_id).first()
    if not item:
        raise HTTPException(404, "Request not found")
    db.delete(item)
    db.commit()
    return {"ok": True}
