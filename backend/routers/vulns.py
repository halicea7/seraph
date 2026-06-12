from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import uuid

from database import get_db, VulnerabilityRecord, Finding, AppSetting
from services.ai_client import chat_complete, load_llm_params

router = APIRouter(prefix="/vulns", tags=["vulns"])

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class CreateVulnRequest(BaseModel):
    project_id: str
    title: str
    description: str = ""
    severity: str = "medium"
    cvss_score: Optional[str] = None
    cve_id: Optional[str] = None
    affected_asset: str = ""
    remediation_notes: str = ""
    tags: str = ""
    finding_id: Optional[str] = None


class UpdateVulnRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    cvss_score: Optional[str] = None
    cve_id: Optional[str] = None
    affected_asset: Optional[str] = None
    remediation_notes: Optional[str] = None
    tags: Optional[str] = None


class ImportFindingsRequest(BaseModel):
    project_id: str
    finding_ids: list[str]


def _row(v: VulnerabilityRecord) -> dict:
    return {
        "id": v.id,
        "project_id": v.project_id,
        "title": v.title,
        "description": v.description,
        "severity": v.severity,
        "status": v.status,
        "cvss_score": v.cvss_score,
        "cve_id": v.cve_id,
        "affected_asset": v.affected_asset,
        "remediation_notes": v.remediation_notes,
        "ai_remediation": v.ai_remediation,
        "finding_id": v.finding_id,
        "tags": v.tags,
        "created_at": v.created_at.isoformat() if v.created_at else None,
        "updated_at": v.updated_at.isoformat() if v.updated_at else None,
    }


def _get_setting(db: Session, key: str, default: str = "") -> str:
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    return row.value if row else default


@router.get("")
def list_vulns(
    project_id: str,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(VulnerabilityRecord).filter(VulnerabilityRecord.project_id == project_id)
    if status and status != "all":
        q = q.filter(VulnerabilityRecord.status == status)
    if severity and severity != "all":
        q = q.filter(VulnerabilityRecord.severity == severity)
    return [_row(v) for v in q.order_by(VulnerabilityRecord.created_at.desc()).all()]


@router.get("/stats")
def vuln_stats(project_id: str, db: Session = Depends(get_db)):
    vulns = db.query(VulnerabilityRecord).filter(
        VulnerabilityRecord.project_id == project_id
    ).all()
    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for v in vulns:
        by_status[v.status] = by_status.get(v.status, 0) + 1
        by_severity[v.severity] = by_severity.get(v.severity, 0) + 1
    return {"total": len(vulns), "by_status": by_status, "by_severity": by_severity}


@router.post("")
def create_vuln(req: CreateVulnRequest, db: Session = Depends(get_db)):
    vuln = VulnerabilityRecord(
        id=str(uuid.uuid4()),
        project_id=req.project_id,
        title=req.title,
        description=req.description,
        severity=req.severity,
        cvss_score=req.cvss_score,
        cve_id=req.cve_id,
        affected_asset=req.affected_asset,
        remediation_notes=req.remediation_notes,
        tags=req.tags,
        finding_id=req.finding_id,
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    return _row(vuln)


@router.get("/{vuln_id}")
def get_vuln(vuln_id: str, db: Session = Depends(get_db)):
    vuln = db.query(VulnerabilityRecord).filter(VulnerabilityRecord.id == vuln_id).first()
    if not vuln:
        raise HTTPException(404, "Vulnerability not found")
    return _row(vuln)


@router.put("/{vuln_id}")
def update_vuln(vuln_id: str, req: UpdateVulnRequest, db: Session = Depends(get_db)):
    vuln = db.query(VulnerabilityRecord).filter(VulnerabilityRecord.id == vuln_id).first()
    if not vuln:
        raise HTTPException(404, "Vulnerability not found")
    if req.title is not None:
        vuln.title = req.title
    if req.description is not None:
        vuln.description = req.description
    if req.severity is not None:
        vuln.severity = req.severity
    if req.status is not None:
        vuln.status = req.status
    if req.cvss_score is not None:
        vuln.cvss_score = req.cvss_score
    if req.cve_id is not None:
        vuln.cve_id = req.cve_id
    if req.affected_asset is not None:
        vuln.affected_asset = req.affected_asset
    if req.remediation_notes is not None:
        vuln.remediation_notes = req.remediation_notes
    if req.tags is not None:
        vuln.tags = req.tags
    vuln.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(vuln)
    return _row(vuln)


@router.delete("/{vuln_id}")
def delete_vuln(vuln_id: str, db: Session = Depends(get_db)):
    vuln = db.query(VulnerabilityRecord).filter(VulnerabilityRecord.id == vuln_id).first()
    if not vuln:
        raise HTTPException(404, "Vulnerability not found")
    db.delete(vuln)
    db.commit()
    return {"ok": True}


@router.post("/import-findings")
def import_findings(req: ImportFindingsRequest, db: Session = Depends(get_db)):
    findings = db.query(Finding).filter(Finding.id.in_(req.finding_ids)).all()
    created = 0
    for f in findings:
        existing = db.query(VulnerabilityRecord).filter(
            VulnerabilityRecord.finding_id == f.id
        ).first()
        if existing:
            continue
        vuln = VulnerabilityRecord(
            id=str(uuid.uuid4()),
            project_id=req.project_id,
            title=f.title,
            description=f.description or "",
            severity=f.severity,
            cve_id=f.cve_id,
            cvss_score=f.cvss_score,
            affected_asset="",
            remediation_notes=f.remediation or "",
            finding_id=f.id,
        )
        db.add(vuln)
        created += 1
    db.commit()
    return {"imported": created}


@router.post("/{vuln_id}/ai-remediate")
def ai_remediate(vuln_id: str, payload: dict = Body(default={}), db: Session = Depends(get_db)):
    """AI remediation for a vuln record. With messages_only=true returns the assembled
    prompt (so a [Local] model can run client-side); otherwise runs the [Server] model
    and persists the result. With result=<text> persists a client-run (local) result."""
    vuln = db.query(VulnerabilityRecord).filter(VulnerabilityRecord.id == vuln_id).first()
    if not vuln:
        raise HTTPException(404, "Vulnerability not found")

    # Persist a client-run (local-model) result, so local and server behave the same.
    if payload.get("result"):
        vuln.ai_remediation = str(payload["result"])
        vuln.updated_at = datetime.utcnow()
        db.commit()
        return {"ai_remediation": vuln.ai_remediation}

    prompt = (
        f"You are a cybersecurity engineer providing remediation guidance.\n\n"
        f"Vulnerability: {vuln.title}\n"
        f"Severity: {vuln.severity.upper()}\n"
        f"CVE: {vuln.cve_id or 'N/A'}\n"
        f"CVSS: {vuln.cvss_score or 'N/A'}\n"
        f"Affected Asset: {vuln.affected_asset or 'Unknown'}\n"
        f"Description: {(vuln.description or 'No description provided.')[:500]}\n\n"
        f"Provide specific, actionable remediation steps. Include:\n"
        f"1. Immediate mitigations (quick wins)\n"
        f"2. Long-term fix with specific commands or configuration changes\n"
        f"3. Verification steps to confirm the fix is applied\n"
        f"4. Any relevant CVE patches or vendor advisories\n"
        f"Be concise and technical. Use numbered steps."
    )
    messages = [{"role": "user", "content": prompt}]
    if payload.get("messages_only"):
        return {"messages": messages}

    endpoint = _get_setting(db, "ai_endpoint", "http://localhost:11434")
    model = payload.get("model") or _get_setting(db, "ai_model", "")
    if not model:
        raise HTTPException(400, "No AI model configured. Go to Settings → AI to set one.")
    try:
        result = chat_complete(endpoint, model, messages, **load_llm_params(db))
        vuln.ai_remediation = result
        vuln.updated_at = datetime.utcnow()
        db.commit()
        return {"ai_remediation": result}
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))
