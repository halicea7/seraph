import json
import re
import shutil
import subprocess

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database import Finding, Scan, get_db
from services.cve_enricher import extract_cve_ids, fetch_cve

router = APIRouter(tags=["enrichment"])


# ── Searchsploit / MSF module search ─────────────────────────────────────────

def _run_searchsploit(query: str) -> list[dict]:
    """Run searchsploit and return parsed results."""
    if not shutil.which("searchsploit"):
        return []
    # Sanitise query — allow only alphanumeric, spaces, hyphens, dots
    safe_query = re.sub(r"[^a-zA-Z0-9 .\-]", "", query)[:100]
    if not safe_query:
        return []
    try:
        proc = subprocess.run(
            ["searchsploit", "--json", safe_query],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
        data = json.loads(proc.stdout)
        results = []
        for item in data.get("RESULTS_EXPLOIT", []):
            results.append({
                "title": item.get("Title", ""),
                "edb_id": item.get("EDB-ID", ""),
                "type": item.get("Type", ""),
                "platform": item.get("Platform", ""),
                "path": item.get("Path", ""),
                "codes": item.get("Codes", ""),  # CVE IDs
                "is_msf": "metasploit" in item.get("Path", "").lower(),
            })
        return results
    except Exception:
        return []


def _run_msf_search(query: str) -> list[dict]:
    """Search Metasploit Framework modules for matching exploit/auxiliary modules."""
    if not shutil.which("msfconsole"):
        return []
    safe_query = re.sub(r"[^a-zA-Z0-9 .\-_/]", "", query)[:100]
    if not safe_query:
        return []
    try:
        proc = subprocess.run(
            ["msfconsole", "-q", "-x", f"search {safe_query}; exit"],
            capture_output=True, text=True, timeout=60,
        )
        output = proc.stdout or ""
        # Parse the table output
        modules = []
        in_table = False
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("Name") and "Rank" in stripped:
                in_table = True
                continue
            if in_table and stripped.startswith("="):
                continue
            if in_table and not stripped:
                continue
            if in_table and stripped.startswith("\\_ "):
                # Alias / target line, skip
                continue
            if in_table and stripped:
                parts = stripped.split(None, 4)
                if len(parts) >= 2 and "/" in parts[1]:
                    modules.append({
                        "name": parts[1],
                        "rank": parts[3] if len(parts) > 3 else "",
                        "description": parts[4] if len(parts) > 4 else "",
                    })
        return modules
    except Exception:
        return []


def _apply_cve(finding: Finding, cve_data: dict) -> None:
    finding.cve_id = cve_data["cve_id"]
    finding.cvss_score = cve_data["cvss_score"]
    if cve_data["description"] and not finding.description:
        finding.description = cve_data["description"]
    if cve_data["references"]:
        refs = "\n".join(cve_data["references"])
        finding.remediation = f"{finding.remediation or ''}\n\nReferences:\n{refs}".strip()


@router.post("/findings/{finding_id}/enrich")
def enrich_finding(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")

    cve_ids = extract_cve_ids(f"{finding.title} {finding.description or ''}")
    if not cve_ids:
        return {"status": "no_cve"}

    cve_data = fetch_cve(cve_ids[0])
    if not cve_data:
        return {"status": "not_found", "cve_id": cve_ids[0]}

    _apply_cve(finding, cve_data)
    db.commit()
    db.refresh(finding)
    return {"status": "enriched", **cve_data}


@router.post("/scans/{scan_id}/enrich")
def enrich_scan(scan_id: str, db: Session = Depends(get_db)):
    if not db.query(Scan).filter(Scan.id == scan_id).first():
        raise HTTPException(404, "Scan not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    enriched = 0

    for finding in findings:
        cve_ids = extract_cve_ids(f"{finding.title} {finding.description or ''}")
        if not cve_ids:
            continue
        cve_data = fetch_cve(cve_ids[0])
        if not cve_data:
            continue
        _apply_cve(finding, cve_data)
        enriched += 1

    db.commit()
    return {"enriched": enriched, "total": len(findings)}


@router.get("/findings/{finding_id}/searchsploit")
def searchsploit_finding(finding_id: str, db: Session = Depends(get_db)):
    """
    Search ExploitDB via searchsploit using the finding's CVE ID and/or title.
    Returns matching exploits, flagging those that are Metasploit modules.
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")

    results = []
    # Search by CVE ID first (most precise)
    if finding.cve_id:
        results = _run_searchsploit(finding.cve_id)
    # Fall back to title keywords if no CVE or no results
    if not results:
        results = _run_searchsploit(finding.title[:60])

    return {
        "finding_id": finding_id,
        "query": finding.cve_id or finding.title[:60],
        "results": results,
        "msf_matches": [r for r in results if r["is_msf"]],
    }


@router.get("/searchsploit")
def searchsploit_query(q: str = Query(..., max_length=100)):
    """Generic searchsploit query endpoint."""
    return {"query": q, "results": _run_searchsploit(q)}


@router.get("/findings/{finding_id}/msf-modules")
def msf_modules_for_finding(finding_id: str, db: Session = Depends(get_db)):
    """
    Search Metasploit for modules matching a finding's CVE ID or title keywords.
    Returns ranked module list.
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")

    query = finding.cve_id or finding.title[:60]
    modules = _run_msf_search(query)
    return {
        "finding_id": finding_id,
        "query": query,
        "modules": modules,
    }


@router.get("/msf-modules")
def msf_module_search(q: str = Query(..., max_length=100)):
    """Generic MSF module search endpoint."""
    return {"query": q, "modules": _run_msf_search(q)}
