"""
PTES knowledge base endpoints.

GET  /ai/ptes/status          — index stats
POST /ai/ptes/sync            — re-download and re-index
GET  /ai/ptes/search?q=...    — FTS keyword search
GET  /ai/ptes/phase/{id}      — all sections for a phase
"""

from fastapi import APIRouter, HTTPException, Query

from services.ptes_index import get_status, search, get_by_phase, sync, _sync_lock

router = APIRouter(prefix="/ai/ptes", tags=["ptes"])


@router.get("/status")
def ptes_status():
    return get_status()


@router.post("/sync")
def trigger_sync():
    if not _sync_lock.acquire(blocking=False):
        return {"ok": False, "message": "Sync already in progress"}
    _sync_lock.release()
    sync(background=True)
    return {"ok": True, "message": "Sync started in background"}


@router.get("/search")
def search_ptes(
    q: str = Query(..., min_length=1),
    limit: int = Query(3, ge=1, le=10),
):
    results = search(q, limit=limit)
    return {"results": results, "count": len(results)}


@router.get("/phase/{phase_id}")
def phase_sections(phase_id: str):
    results = get_by_phase(phase_id)
    if not results:
        raise HTTPException(404, f"Phase {phase_id!r} not found or index empty")
    return {"phase_id": phase_id, "results": results}
