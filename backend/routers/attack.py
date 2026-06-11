"""
MITRE ATT&CK knowledge base endpoints.

GET  /ai/attack/status             — index stats (count, last sync, sync state)
POST /ai/attack/sync               — trigger re-download and re-index (background)
GET  /ai/attack/search?q=...       — FTS keyword search
GET  /ai/attack/technique/{id}     — direct T-ID lookup
GET  /ai/attack/tactic/{tactic}    — list techniques by tactic
"""

import json
import re

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database import get_db, Finding, Scan, Target, PlaybookRun, Playbook
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

# Matches T1003 and sub-techniques like T1003.001 as whole tokens.
_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _extract_tids(*texts: str | None) -> list[str]:
    """Pull all ATT&CK technique IDs out of arbitrary free text."""
    found: list[str] = []
    for text in texts:
        if text:
            found.extend(m.group(0).upper() for m in _TID_RE.finditer(text))
    return found


def _compute_coverage(db: Session, project_id: str) -> dict[str, dict]:
    """Tally ATT&CK technique usage for a project from findings + playbook runs.

    Returns a map of technique_id -> {score, sources:set}. A technique's score is
    the number of times it was referenced across all sources.
    """
    coverage: dict[str, dict] = {}

    def _bump(tid: str, source: str) -> None:
        entry = coverage.setdefault(tid, {"score": 0, "sources": set()})
        entry["score"] += 1
        entry["sources"].add(source)

    # Findings for this project: Finding -> Scan -> Target(project_id)
    findings = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
        .filter(Target.project_id == project_id)
        .all()
    )
    for f in findings:
        for tid in _extract_tids(f.tags, f.description, f.exploit_chain_json):
            _bump(tid, "finding")

    # Playbook runs for this project -> the playbook's declared techniques
    runs = db.query(PlaybookRun).filter(PlaybookRun.project_id == project_id).all()
    pb_cache: dict[str, list[str]] = {}
    for run in runs:
        if run.playbook_id not in pb_cache:
            pb = db.query(Playbook).filter(Playbook.id == run.playbook_id).first()
            try:
                pb_cache[run.playbook_id] = json.loads(pb.mitre_techniques) if pb else []
            except (json.JSONDecodeError, TypeError):
                pb_cache[run.playbook_id] = []
        for tid in pb_cache[run.playbook_id]:
            _bump(str(tid).upper(), "playbook")

    return coverage


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


def _enrich_and_group(coverage: dict[str, dict]) -> tuple[list[dict], list[dict]]:
    """Turn a raw coverage map into a flat list + a per-tactic grouping.

    Enriches each touched technique with its name/tactic from the ATT&CK index.
    Sub-techniques (T1003.001) fall back to the parent (T1003) for metadata.
    A technique appears under every tactic it belongs to.
    """
    flat: list[dict] = []
    by_tactic: dict[str, list[dict]] = {}

    for tid, data in coverage.items():
        meta = get_by_id(tid) or get_by_id(tid.split(".")[0]) or {}
        item = {
            "technique_id": tid,
            "name": meta.get("name", ""),
            "tactic": meta.get("tactic", ""),
            "score": data["score"],
            "sources": sorted(data["sources"]),
        }
        flat.append(item)
        tactics = [t.strip() for t in (meta.get("tactic") or "").split(",") if t.strip()]
        for t in tactics or ["(unmapped)"]:
            by_tactic.setdefault(t, []).append(item)

    flat.sort(key=lambda x: (-x["score"], x["technique_id"]))
    grouped = [
        {
            "tactic": tactic,
            "techniques": sorted(items, key=lambda x: (-x["score"], x["technique_id"])),
        }
        for tactic, items in sorted(by_tactic.items())
    ]
    return flat, grouped


@router.get("/coverage")
def technique_coverage(
    project_id: str = Query(..., description="Project to compute coverage for"),
    db: Session = Depends(get_db),
):
    """ATT&CK technique coverage for an engagement.

    Scores each technique by how often it was referenced across the project's
    findings and playbook runs. Powers the Navigator heatmap.
    """
    coverage = _compute_coverage(db, project_id)
    flat, grouped = _enrich_and_group(coverage)
    max_score = max((t["score"] for t in flat), default=0)
    return {
        "project_id": project_id,
        "total_touched": len(flat),
        "max_score": max_score,
        "tactics": grouped,
        "techniques": flat,
    }


@router.get("/coverage/export")
def export_navigator_layer(
    project_id: str = Query(...),
    name: str = Query("Seraph Coverage"),
    db: Session = Depends(get_db),
):
    """Export coverage as an ATT&CK Navigator layer (importable at mitre-attack.github.io/attack-navigator)."""
    coverage = _compute_coverage(db, project_id)
    flat, _ = _enrich_and_group(coverage)
    max_score = max((t["score"] for t in flat), default=1) or 1
    return {
        "name": name,
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Seraph engagement coverage — {len(flat)} techniques touched.",
        "sorting": 3,
        "hideDisabled": False,
        "techniques": [
            {
                "techniqueID": t["technique_id"],
                "score": t["score"],
                "comment": ", ".join(t["sources"]),
                "enabled": True,
            }
            for t in flat
        ],
        "gradient": {
            "colors": ["#f0a83a33", "#e85c4eff"],
            "minValue": 0,
            "maxValue": max_score,
        },
        "legendItems": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#1a1814",
    }
