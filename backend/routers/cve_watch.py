"""
CVE Watch API — list watched services for a project or target.
"""

import asyncio
import json
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import Target, WatchedService, get_db

router = APIRouter(prefix="/cve-watch", tags=["cve_watch"])


@router.get("")
def list_watched_services(
    project_id: str = Query(None),
    target_id: str = Query(None),
    db: Session = Depends(get_db),
):
    """Return all WatchedService rows, optionally filtered by project or target."""
    q = db.query(WatchedService)

    if target_id:
        q = q.filter(WatchedService.target_id == target_id)
    elif project_id:
        target_ids = [
            t.id for t in db.query(Target).filter(Target.project_id == project_id).all()
        ]
        if not target_ids:
            return []
        q = q.filter(WatchedService.target_id.in_(target_ids))

    rows = q.order_by(WatchedService.created_at).all()
    return [
        {
            "id": ws.id,
            "target_id": ws.target_id,
            "service_term": ws.service_term,
            "last_checked": ws.last_checked.isoformat() if ws.last_checked else None,
            "known_cves": json.loads(ws.known_cves or "[]"),
            "created_at": ws.created_at.isoformat() if ws.created_at else None,
        }
        for ws in rows
    ]


class AddWatchedServiceRequest(BaseModel):
    target_id: str
    service_term: str


@router.post("")
def add_watched_service(req: AddWatchedServiceRequest, db: Session = Depends(get_db)):
    """Manually add a service term to the CVE watchlist for a target."""
    target = db.query(Target).filter(Target.id == req.target_id).first()
    if not target:
        raise HTTPException(404, "Target not found")
    service_term = req.service_term.strip()[:80]
    if not service_term:
        raise HTTPException(400, "service_term required")
    existing = db.query(WatchedService).filter(
        WatchedService.target_id == req.target_id,
        WatchedService.service_term == service_term,
    ).first()
    if existing:
        return {"id": existing.id, "already_exists": True}
    ws = WatchedService(
        id=str(uuid.uuid4()),
        target_id=req.target_id,
        service_term=service_term,
    )
    db.add(ws)
    db.commit()
    return {"id": ws.id, "created": True}


@router.delete("/{ws_id}")
def delete_watched_service(ws_id: str, db: Session = Depends(get_db)):
    """Remove a watched service entry."""
    ws = db.query(WatchedService).filter(WatchedService.id == ws_id).first()
    if not ws:
        raise HTTPException(404, "Not found")
    db.delete(ws)
    db.commit()
    return {"deleted": ws_id}


@router.post("/{ws_id}/check")
async def trigger_cve_check(ws_id: str, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Manually trigger a CVE check for a single watched service."""
    ws = db.query(WatchedService).filter(WatchedService.id == ws_id).first()
    if not ws:
        raise HTTPException(404, "Not found")
    from services.cve_watcher import check_service

    async def _check():
        await check_service(ws_id)

    background_tasks.add_task(asyncio.ensure_future, _check())
    return {"triggered": ws_id, "service_term": ws.service_term}


@router.post("/check-all")
async def trigger_all_cve_checks(background_tasks: BackgroundTasks):
    """Manually trigger CVE checks for all watched services."""
    from services.cve_watcher import check_all_watched_services

    async def _run():
        await check_all_watched_services()

    background_tasks.add_task(asyncio.ensure_future, _run())
    return {"triggered": True}
