from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import Response
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
import json
import uuid
from datetime import datetime
from pathlib import Path

from database import get_db, FPSuppressionRule, Scan, Target, Project, Finding
from services.script_generator import generate_script
from services.executor import run_command_streaming

router = APIRouter(prefix="/audit", tags=["audit"])

# Load scan categories
_categories_path = Path(__file__).parent.parent / "data" / "scan_categories.json"
with open(_categories_path) as f:
    SCAN_CATEGORIES = json.load(f)


@router.get("/categories")
def get_scan_categories():
    return SCAN_CATEGORIES


class GenerateScriptRequest(BaseModel):
    project_id: str
    target_id: str
    scan_categories: list[dict]  # [{category_id, config}]
    credential_id: Optional[str] = None  # SSH key credential for remote host scans


@router.post("/generate")
def generate_audit_script(req: GenerateScriptRequest, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == req.target_id).first()
    if not target:
        raise HTTPException(404, "Target not found")
    project = db.query(Project).filter(Project.id == req.project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")

    script = generate_script(
        project_name=project.name,
        target=target.hostname_or_ip,
        scan_categories=req.scan_categories,
    )

    config: dict = {"categories": req.scan_categories}
    if req.credential_id:
        config["credential_id"] = req.credential_id

    scan = Scan(
        id=str(uuid.uuid4()),
        target_id=req.target_id,
        scan_type=",".join(c["category_id"] for c in req.scan_categories),
        module="audit",
        status="pending",
        config_json=json.dumps(config),
        started_at=None,
        completed_at=None,
        raw_output=None,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    uses_ssh = bool(req.credential_id)
    return {"scan_id": scan.id, "script": script, "uses_ssh": uses_ssh}


@router.get("/script/{scan_id}/download")
def download_script(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    config = json.loads(scan.config_json or "{}")
    categories = config.get("categories", [])
    target = db.query(Target).filter(Target.id == scan.target_id).first()
    project = db.query(Project).filter(Project.id == target.project_id).first() if target else None

    script = generate_script(
        project_name=project.name if project else "Unknown",
        target=target.hostname_or_ip if target else "unknown",
        scan_categories=categories,
    )

    return Response(
        content=script,
        media_type="text/x-shellscript",
        headers={"Content-Disposition": f"attachment; filename=seraph_audit_{scan_id[:8]}.sh"},
    )


@router.get("/scans")
def list_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).filter(Scan.module == "audit").order_by(Scan.id.desc()).limit(50).all()
    return scans


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@router.post("/scans/{scan_id}/parse")
def parse_scan_findings(scan_id: str, db: Session = Depends(get_db)):
    """Parse raw scan output and create Finding records."""
    from services.output_parser import auto_parse_scan_output

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    if not scan.raw_output:
        raise HTTPException(400, "Scan has no output to parse")

    parsed = auto_parse_scan_output(scan.scan_type, scan.raw_output)

    # Delete existing findings for this scan
    db.query(Finding).filter(Finding.scan_id == scan_id).delete()

    # Load project-level FP suppression rules once
    target = db.query(Target).filter(Target.id == scan.target_id).first()
    fp_rules = []
    if target:
        fp_rules = db.query(FPSuppressionRule).filter(
            FPSuppressionRule.project_id == target.project_id
        ).all()

    def _is_auto_fp(title: str, tool: str) -> bool:
        """Return True if a suppression rule matches this finding."""
        title_lc = title.lower()
        tool_lc = tool.lower() if tool else ""
        for rule in fp_rules:
            if rule.tool and rule.tool.lower() not in tool_lc:
                continue
            if rule.title_contains.lower() in title_lc:
                return True
        return False

    created = []
    for pf in parsed:
        extra = ",".join(t for t in (pf.extra_tags or []) if t)
        auto_fp = _is_auto_fp(pf.title or "", scan.scan_type or "")
        finding = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            severity=pf.severity,
            title=pf.title,
            description=pf.description,
            control_id=pf.control_id,
            framework=pf.framework,
            remediation=pf.remediation,
            evidence=pf.evidence,
            cve_id=pf.cve_id,
            tags=extra,
            status="false_positive" if auto_fp else "open",
            fp_reason="Auto-suppressed by project rule" if auto_fp else None,
        )
        db.add(finding)
        created.append(finding)

    db.commit()

    # Push a notification so the dashboard dot lights up
    if created:
        from routers.notifications import push_notification
        highs = sum(1 for f in created if f.severity in ("critical", "high"))
        target = db.query(Target).filter(Target.id == scan.target_id).first()
        target_label = target.hostname_or_ip if target else "unknown"
        push_notification(
            db,
            title=f"{len(created)} finding(s) parsed — {target_label}",
            body=(f"{highs} critical/high" if highs else "No critical/high findings") + f" · scan {scan_id[:8]}",
            type="critical" if highs > 0 else "info",
        )

    # Auto-enrich findings that already have a CVE ID extracted during parsing
    findings_with_cve = [f for f in created if f.cve_id]
    if findings_with_cve:
        import threading
        from services.cve_enricher import fetch_cve

        def _enrich_bg():
            from database import SessionLocal
            bg_db = SessionLocal()
            try:
                for f in findings_with_cve:
                    data = fetch_cve(f.cve_id)
                    if data:
                        row = bg_db.query(Finding).filter(Finding.id == f.id).first()
                        if row:
                            row.cvss_score = data.get("cvss_score")
                            if not row.description and data.get("description"):
                                row.description = data["description"]
                bg_db.commit()
            finally:
                bg_db.close()

        threading.Thread(target=_enrich_bg, daemon=True).start()

    return {"parsed": len(created), "findings": [{"id": f.id, "title": f.title, "severity": f.severity} for f in created]}


@router.get("/findings")
def list_all_findings(project_id: Optional[str] = None, severity: Optional[str] = None, db: Session = Depends(get_db)):
    """List findings, optionally filtered by project or severity."""
    query = db.query(Finding)
    if severity:
        query = query.filter(Finding.severity == severity)
    findings = query.order_by(Finding.id.desc()).limit(500).all()
    return findings


@router.get("/scans/{scan_id}/findings")
def get_scan_findings(scan_id: str, db: Session = Depends(get_db)):
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    return findings


_VALID_REPORT_TYPES = {"audit", "pentest", "executive_summary", "technical_detail", "compliance_mapped"}


class GenerateReportRequest(BaseModel):
    project_id: str
    report_type: str = "audit"  # "audit" | "pentest" | "executive_summary" | "technical_detail" | "compliance_mapped"
    scan_ids: Optional[list[str]] = None  # None means all scans for project
    auditor: str = "Seraph (Automated)"


@router.post("/reports/generate")
def generate_project_report(req: GenerateReportRequest, db: Session = Depends(get_db)):
    """Generate a report for a project. report_type: audit | pentest | executive_summary | technical_detail | compliance_mapped"""
    if req.report_type not in _VALID_REPORT_TYPES:
        raise HTTPException(400, f"report_type must be one of: {sorted(_VALID_REPORT_TYPES)}")
    project = db.query(Project).filter(Project.id == req.project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")

    targets = db.query(Target).filter(Target.project_id == req.project_id).all()

    # Get scans
    if req.scan_ids:
        scans = db.query(Scan).filter(Scan.id.in_(req.scan_ids)).all()
    else:
        target_ids = [t.id for t in targets]
        scans = db.query(Scan).filter(Scan.target_id.in_(target_ids)).all() if target_ids else []

    # Get all findings for these scans
    scan_ids = [s.id for s in scans]
    findings = db.query(Finding).filter(Finding.scan_id.in_(scan_ids)).all() if scan_ids else []

    # Serialize
    targets_data = [{"id": t.id, "hostname_or_ip": t.hostname_or_ip, "target_type": t.target_type, "notes": t.notes or ""} for t in targets]
    scans_data = [{"id": s.id, "scan_type": s.scan_type, "status": s.status, "completed_at": str(s.completed_at) if s.completed_at else None} for s in scans]
    findings_data = [{"id": f.id, "title": f.title, "description": f.description, "severity": f.severity, "control_id": f.control_id, "framework": f.framework, "remediation": f.remediation, "evidence": f.evidence} for f in findings]

    from services.report_generator import generate_report
    report = generate_report(
        project_name=project.name,
        report_type=req.report_type,
        targets=targets_data,
        scans=scans_data,
        findings=findings_data,
        auditor=req.auditor,
    )

    return report


@router.get("/reports/download/{project_id}")
def download_report(project_id: str, format: str = "html", auditor: str = "Seraph (Automated)", db: Session = Depends(get_db)):
    """Download a report as HTML or Markdown."""
    from fastapi.responses import Response as FastAPIResponse

    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")

    targets = db.query(Target).filter(Target.project_id == project_id).all()
    target_ids = [t.id for t in targets]
    scans = db.query(Scan).filter(Scan.target_id.in_(target_ids)).all() if target_ids else []
    scan_ids = [s.id for s in scans]
    findings = db.query(Finding).filter(Finding.scan_id.in_(scan_ids)).all() if scan_ids else []

    targets_data = [{"id": t.id, "hostname_or_ip": t.hostname_or_ip, "target_type": t.target_type, "notes": t.notes or ""} for t in targets]
    scans_data = [{"id": s.id, "scan_type": s.scan_type, "status": s.status, "completed_at": str(s.completed_at) if s.completed_at else None} for s in scans]
    findings_data = [{"id": f.id, "title": f.title, "description": f.description, "severity": f.severity, "control_id": f.control_id, "framework": f.framework, "remediation": f.remediation, "evidence": f.evidence} for f in findings]

    from services.report_generator import generate_report
    report = generate_report(
        project_name=project.name,
        report_type="audit",
        targets=targets_data,
        scans=scans_data,
        findings=findings_data,
        auditor=auditor,
    )

    if format == "markdown" or format == "md":
        return FastAPIResponse(
            content=report["markdown"],
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="seraph_{project_id[:8]}_report.md"'},
        )
    else:
        return FastAPIResponse(
            content=report["html"],
            media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="seraph_{project_id[:8]}_report.html"'},
        )


@router.get("/reports/pdf/{project_id}")
def download_pdf_report(project_id: str, db: Session = Depends(get_db)):
    """Export report as a PDF using WeasyPrint."""
    try:
        import weasyprint  # type: ignore
    except ImportError:
        raise HTTPException(501, "WeasyPrint not installed. Run: pip install weasyprint")

    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")

    targets = db.query(Target).filter(Target.project_id == project_id).all()
    target_ids = [t.id for t in targets]
    scans = db.query(Scan).filter(Scan.target_id.in_(target_ids)).all() if target_ids else []
    scan_ids = [s.id for s in scans]
    findings = db.query(Finding).filter(Finding.scan_id.in_(scan_ids)).all() if scan_ids else []

    targets_data = [{"id": t.id, "hostname_or_ip": t.hostname_or_ip, "target_type": t.target_type, "notes": t.notes or ""} for t in targets]
    scans_data = [{"id": s.id, "scan_type": s.scan_type, "status": s.status, "completed_at": str(s.completed_at) if s.completed_at else None} for s in scans]
    findings_data = [{"id": f.id, "title": f.title, "description": f.description, "severity": f.severity, "control_id": f.control_id, "framework": f.framework, "remediation": f.remediation, "evidence": f.evidence} for f in findings]

    from services.report_generator import generate_report
    report = generate_report(
        project_name=project.name,
        report_type="audit",
        targets=targets_data,
        scans=scans_data,
        findings=findings_data,
    )

    pdf_bytes = weasyprint.HTML(string=report["html"]).write_pdf()
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="seraph_{project_id[:8]}_report.pdf"'},
    )
