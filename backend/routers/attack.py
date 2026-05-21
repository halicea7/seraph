"""
MITRE ATT&CK knowledge base endpoints.

GET  /ai/attack/status             — index stats (count, last sync, sync state)
POST /ai/attack/sync               — trigger re-download and re-index (background)
GET  /ai/attack/search?q=...       — FTS keyword search
GET  /ai/attack/technique/{id}     — direct T-ID lookup
GET  /ai/attack/tactic/{tactic}    — list techniques by tactic
"""

from fastapi import APIRouter, HTTPException, Query

from services.attack_index import (
    get_status,
    get_by_id,
    get_by_tactic,
    list_tactics,
    browse,
    search,
    sync,
    _sync_lock,
)

router = APIRouter(prefix="/ai/attack", tags=["attack"])


@router.get("/status")
def attack_status():
    return get_status()


@router.post("/sync")
def trigger_sync():
    """Re-download and re-index the ATT&CK dataset in the background."""
    if not _sync_lock.acquire(blocking=False):
        return {"ok": False, "message": "Sync already in progress"}
    _sync_lock.release()
    sync(background=True)
    return {"ok": True, "message": "Sync started in background"}


@router.get("/search")
def search_techniques(
    q: str = Query(..., min_length=1, description="Search query or T-ID"),
    limit: int = Query(5, ge=1, le=20),
):
    results = search(q, limit=limit)
    return {"results": results, "count": len(results)}


@router.get("/technique/{technique_id}")
def get_technique(technique_id: str):
    technique = get_by_id(technique_id)
    if not technique:
        raise HTTPException(404, f"Technique {technique_id!r} not found in index")
    return technique


@router.get("/tactic/{tactic}")
def list_by_tactic(tactic: str, limit: int = Query(20, ge=1, le=50)):
    results = get_by_tactic(tactic, limit=limit)
    return {"tactic": tactic, "results": results, "count": len(results)}


@router.get("/tactics")
def get_tactics():
    """Return all distinct tactics in the index."""
    return {"tactics": list_tactics()}


@router.get("/browse")
def browse_techniques(
    tactic: str = Query("", description="Filter by tactic slug"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """Paginated browse of all indexed techniques."""
    return browse(tactic=tactic, limit=limit, offset=offset)
