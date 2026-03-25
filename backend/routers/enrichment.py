from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import Finding, Scan, get_db
from services.cve_enricher import extract_cve_ids, fetch_cve

router = APIRouter(tags=["enrichment"])


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
