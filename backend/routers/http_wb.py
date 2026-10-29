"""
HTTP Request Workbench.

Repeater/Intruder-lite: send/replay a single HTTP request, fuzz a §FUZZ§ marker
across payloads (streamed over /ws/httpfuzz/{run_id}), and persist a per-project
request collection. Scope is enforced on the request host before anything is sent.
"""

import json
import time
from datetime import datetime
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db, Project, HttpRequestItem, HttpCookie
from services.scope_service import check_scope
from services.http_workbench import send_request, create_fuzz_job
from services.cookie_jar import ingest_set_cookie, build_cookie_header

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
    # A target that holds the connection open by design (a reverse-shell
    # listener, a slow-loris-style endpoint) previously hit a hardcoded 20s
    # timeout buried in services.http_workbench, surfaced only as a generic
    # 502 -- no way to see or change the limit from the UI.
    timeout: float = 30.0


@router.post("/send")
async def http_send(req: SendRequest, db: Session = Depends(get_db)):
    _enforce_scope(db, req.project_id, req.url)
    host = _host(req.url)

    # An explicit Cookie header on the request always wins; otherwise fill
    # one in from this project's jar so logging in once (which populates
    # the jar via the Set-Cookie capture below) keeps every later request
    # against the same host authenticated.
    headers = dict(req.headers)
    if not any(k.lower() == "cookie" for k in headers):
        jar_cookie = build_cookie_header(db, req.project_id, host)
        if jar_cookie:
            headers["Cookie"] = jar_cookie

    t0 = time.perf_counter()
    try:
        result = await send_request(req.method, req.url, headers, req.body, timeout=req.timeout)
    except httpx.TimeoutException:
        elapsed = time.perf_counter() - t0
        raise HTTPException(504, f"Request timed out after {elapsed:.1f}s (limit {req.timeout}s)")
    except Exception as exc:
        raise HTTPException(502, f"Request failed: {exc}")

    set_cookie = result.pop("set_cookie", [])
    if set_cookie:
        ingest_set_cookie(db, req.project_id, host, set_cookie)
    return result


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


# ── Cookie jar ─────────────────────────────────────────────────────────────────

class CookieUpsert(BaseModel):
    project_id: str
    domain: str
    name: str
    value: str = ""


def _cookie_dict(c: HttpCookie) -> dict:
    return {
        "id": c.id,
        "project_id": c.project_id,
        "domain": c.domain,
        "name": c.name,
        "value": c.value,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }


@router.get("/cookies")
def list_cookies(project_id: str, db: Session = Depends(get_db)):
    rows = (
        db.query(HttpCookie)
        .filter(HttpCookie.project_id == project_id)
        .order_by(HttpCookie.domain, HttpCookie.name)
        .all()
    )
    return [_cookie_dict(c) for c in rows]


@router.post("/cookies")
def upsert_cookie(req: CookieUpsert, db: Session = Depends(get_db)):
    """Manual add/edit -- the same (project_id, domain, name) identity the
    Set-Cookie auto-capture upserts on, so editing a cookie the jar learned
    automatically updates that same row instead of creating a duplicate."""
    if not req.domain.strip() or not req.name.strip():
        raise HTTPException(400, "domain and name are required")
    row = (
        db.query(HttpCookie)
        .filter(
            HttpCookie.project_id == req.project_id,
            HttpCookie.domain == req.domain,
            HttpCookie.name == req.name,
        )
        .first()
    )
    if row:
        row.value = req.value
        row.updated_at = datetime.utcnow()
    else:
        row = HttpCookie(project_id=req.project_id, domain=req.domain, name=req.name, value=req.value)
        db.add(row)
    db.commit()
    db.refresh(row)
    return _cookie_dict(row)


@router.delete("/cookies/{cookie_id}")
def delete_cookie(cookie_id: str, db: Session = Depends(get_db)):
    row = db.query(HttpCookie).filter(HttpCookie.id == cookie_id).first()
    if not row:
        raise HTTPException(404, "Cookie not found")
    db.delete(row)
    db.commit()
    return {"ok": True}
