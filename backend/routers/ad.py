"""
Active Directory Attack Suite.

Import a BloodHound/SharpHound collection, render its graph + quick-wins, and
scaffold attack commands (kerberoast / AS-REP / DCSync / delegation) for the
operator to run. Nothing here executes against a target — commands are returned
as text for the Pentest Workbench / AI Operator flow.
"""

import json
from datetime import datetime

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db, ADCollection
from services.ad_analysis import parse_collection, scaffold_action

router = APIRouter(prefix="/ad", tags=["ad"])

MAX_UPLOAD = 50 * 1024 * 1024  # 50 MB


def _collection_summary(c: ADCollection) -> dict:
    return {
        "id": c.id,
        "project_id": c.project_id,
        "name": c.name,
        "domain": c.domain,
        "source": c.source,
        "stats": json.loads(c.stats_json or "{}"),
        "quick_win_count": len(json.loads(c.quick_wins_json or "[]")),
        "imported_at": c.imported_at.isoformat() if c.imported_at else None,
    }


@router.post("/collections/import")
async def import_collection(
    project_id: str = Form(...),
    name: str = Form(""),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    raw = await file.read()
    if not raw:
        raise HTTPException(400, "Empty upload")
    if len(raw) > MAX_UPLOAD:
        raise HTTPException(413, "Collection exceeds 50 MB limit")

    try:
        parsed = parse_collection(raw, file.filename or "collection.json")
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    collection = ADCollection(
        project_id=project_id,
        name=name or file.filename or f"AD collection {datetime.utcnow():%Y-%m-%d}",
        domain=parsed["domain"],
        source="sharphound",
        stats_json=json.dumps(parsed["stats"]),
        nodes_json=json.dumps(parsed["nodes"]),
        edges_json=json.dumps(parsed["edges"]),
        quick_wins_json=json.dumps(parsed["quick_wins"]),
    )
    db.add(collection)
    db.commit()
    db.refresh(collection)
    return _collection_summary(collection)


@router.get("/collections")
def list_collections(project_id: str = Query(...), db: Session = Depends(get_db)):
    rows = (
        db.query(ADCollection)
        .filter(ADCollection.project_id == project_id)
        .order_by(ADCollection.imported_at.desc())
        .all()
    )
    return [_collection_summary(c) for c in rows]


def _get_or_404(db: Session, collection_id: str) -> ADCollection:
    c = db.query(ADCollection).filter(ADCollection.id == collection_id).first()
    if not c:
        raise HTTPException(404, "Collection not found")
    return c


@router.get("/collections/{collection_id}/graph")
def get_graph(collection_id: str, db: Session = Depends(get_db)):
    c = _get_or_404(db, collection_id)
    return {
        "nodes": json.loads(c.nodes_json or "[]"),
        "edges": json.loads(c.edges_json or "[]"),
        "stats": json.loads(c.stats_json or "{}"),
        "domain": c.domain,
    }


@router.get("/collections/{collection_id}/quick-wins")
def get_quick_wins(collection_id: str, db: Session = Depends(get_db)):
    c = _get_or_404(db, collection_id)
    return {"quick_wins": json.loads(c.quick_wins_json or "[]"), "domain": c.domain}


@router.delete("/collections/{collection_id}")
def delete_collection(collection_id: str, db: Session = Depends(get_db)):
    c = _get_or_404(db, collection_id)
    db.delete(c)
    db.commit()
    return {"ok": True}


class ActionRequest(BaseModel):
    kind: str
    domain: str = ""
    user: str = ""
    password: str = ""
    dc_ip: str = ""


@router.post("/actions/scaffold")
def scaffold(req: ActionRequest):
    """Return a templated command for an AD attack — never executed here."""
    try:
        cmd = scaffold_action(
            req.kind,
            domain=req.domain, user=req.user, password=req.password, dc_ip=req.dc_ip,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"kind": req.kind, "command": cmd}
