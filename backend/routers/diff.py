"""
Scan diff service — compares findings between two scans on the same target.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db, Scan, Finding, Target

router = APIRouter(prefix="/diff", tags=["diff"])


@router.get("/scans/{scan_id_a}/{scan_id_b}")
def diff_scans(scan_id_a: str, scan_id_b: str, db: Session = Depends(get_db)):
    """Compare findings between two scans. Returns new, resolved, and unchanged findings."""
    scan_a = db.query(Scan).filter(Scan.id == scan_id_a).first()
    scan_b = db.query(Scan).filter(Scan.id == scan_id_b).first()

    if not scan_a or not scan_b:
        raise HTTPException(404, "One or both scans not found")

    findings_a = db.query(Finding).filter(Finding.scan_id == scan_id_a).all()
    findings_b = db.query(Finding).filter(Finding.scan_id == scan_id_b).all()

    def finding_key(f: Finding) -> str:
        return f"{f.severity}::{f.title.strip().lower()}"

    keys_a = {finding_key(f): f for f in findings_a}
    keys_b = {finding_key(f): f for f in findings_b}

    new_findings = [
        _serialize(f) for k, f in keys_b.items() if k not in keys_a
    ]
    resolved_findings = [
        _serialize(f) for k, f in keys_a.items() if k not in keys_b
    ]
    unchanged_findings = [
        _serialize(f) for k, f in keys_b.items() if k in keys_a
    ]

    target_a = db.query(Target).filter(Target.id == scan_a.target_id).first()

    return {
        "scan_a": {"id": scan_a.id, "scan_type": scan_a.scan_type, "status": scan_a.status, "started_at": str(scan_a.started_at)},
        "scan_b": {"id": scan_b.id, "scan_type": scan_b.scan_type, "status": scan_b.status, "started_at": str(scan_b.started_at)},
        "target": target_a.hostname_or_ip if target_a else "unknown",
        "summary": {
            "new": len(new_findings),
            "resolved": len(resolved_findings),
            "unchanged": len(unchanged_findings),
        },
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "unchanged_findings": unchanged_findings,
    }


@router.get("/target/{target_id}/scans")
def get_target_scans(target_id: str, db: Session = Depends(get_db)):
    """Get all scans for a target that have findings (for diff selection)."""
    scans = (
        db.query(Scan)
        .filter(Scan.target_id == target_id, Scan.status == "completed")
        .order_by(Scan.id.desc())
        .all()
    )
    result = []
    for s in scans:
        finding_count = db.query(Finding).filter(Finding.scan_id == s.id).count()
        result.append({
            "id": s.id,
            "scan_type": s.scan_type,
            "status": s.status,
            "started_at": str(s.started_at) if s.started_at else None,
            "finding_count": finding_count,
        })
    return result


def _serialize(f: Finding) -> dict:
    return {
        "id": f.id,
        "severity": f.severity,
        "title": f.title,
        "description": f.description,
        "control_id": f.control_id,
        "framework": f.framework,
        "remediation": f.remediation,
    }
