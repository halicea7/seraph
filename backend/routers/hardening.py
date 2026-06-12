from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
import re
import uuid
import json
from datetime import datetime

from database import get_db, HardeningReport, Scan

router = APIRouter(prefix="/hardening", tags=["hardening"])

# ── Profile definitions ──────────────────────────────────────────────────────

PROFILES: dict[str, dict] = {
    "cis_l1": {
        "id": "cis_l1",
        "name": "CIS Level 1",
        "description": "Basic security configuration — low overhead, broadly applicable to all systems.",
        "recommended_categories": ["host_hardening", "network_discovery"],
        "controls": [
            {"id": "1.1", "title": "Filesystem Configuration"},
            {"id": "1.2", "title": "Software and Patch Updates"},
            {"id": "2.1", "title": "Time Synchronization (NTP)"},
            {"id": "2.2", "title": "Unnecessary Services Disabled"},
            {"id": "3.1", "title": "Network Parameters — Host Only"},
            {"id": "3.2", "title": "Network Parameters — Router"},
            {"id": "4.1", "title": "Audit Logging Enabled"},
            {"id": "5.1", "title": "Cron and AT Access Control"},
            {"id": "5.2", "title": "SSH Server Configuration"},
            {"id": "5.3", "title": "PAM Configuration"},
            {"id": "5.4", "title": "User Accounts and Passwords"},
            {"id": "6.1", "title": "File Permissions and Ownership"},
        ],
    },
    "cis_l2": {
        "id": "cis_l2",
        "name": "CIS Level 2",
        "description": "Defense-in-depth — higher security controls that may impact usability.",
        "recommended_categories": ["host_hardening", "network_discovery", "openscap"],
        "controls": [
            {"id": "1.1", "title": "Filesystem Configuration"},
            {"id": "1.2", "title": "Software and Patch Updates"},
            {"id": "1.3", "title": "Filesystem Integrity Checking (AIDE)"},
            {"id": "2.1", "title": "Disable Unused Services"},
            {"id": "2.2", "title": "Special Purpose Services"},
            {"id": "3.1", "title": "Network Parameters"},
            {"id": "3.3", "title": "IPv6 Configuration"},
            {"id": "3.4", "title": "TCP Wrappers"},
            {"id": "3.5", "title": "Uncommon Network Protocols"},
            {"id": "4.1", "title": "Configure rsyslog"},
            {"id": "4.2", "title": "Configure journald"},
            {"id": "5.1", "title": "Configure Cron"},
            {"id": "5.2", "title": "SSH Server — Strict Config"},
            {"id": "5.3", "title": "Configure PAM — Password Quality"},
            {"id": "5.4", "title": "User Accounts — Lockout Policy"},
            {"id": "5.5", "title": "Root Account Restrictions"},
            {"id": "6.1", "title": "System File Permissions"},
            {"id": "6.2", "title": "User and Group Audit"},
        ],
    },
    "stig": {
        "id": "stig",
        "name": "DISA STIG",
        "description": "DoD Security Technical Implementation Guide — strict government/military baseline.",
        "recommended_categories": ["host_hardening", "openscap", "network_discovery"],
        "controls": [
            {"id": "V-230221", "title": "OS must be at latest vendor-supported version"},
            {"id": "V-230222", "title": "Security patches must be up to date"},
            {"id": "V-230223", "title": "SSH must use FIPS-approved algorithms"},
            {"id": "V-230224", "title": "Audit logs must be immutable"},
            {"id": "V-230225", "title": "Firewall must be active and configured"},
            {"id": "V-230226", "title": "SELinux must be in enforcing mode"},
            {"id": "V-230227", "title": "AIDE must verify file integrity"},
            {"id": "V-230228", "title": "Root login via SSH must be disabled"},
            {"id": "V-230229", "title": "Password complexity must be enforced"},
            {"id": "V-230230", "title": "Inactive accounts must be locked after 35 days"},
            {"id": "V-230231", "title": "USB mass storage must be disabled"},
            {"id": "V-230232", "title": "Core dumps must be restricted"},
            {"id": "V-230233", "title": "rsyslog must be configured"},
            {"id": "V-230234", "title": "Audit subsystem must be running"},
        ],
    },
}

# ── Lynis output parser ──────────────────────────────────────────────────────

_HARDENING_INDEX_RE = re.compile(r'[Hh]ardening\s+index\s*[:\|=\[]\s*(\d+)', re.I)
_WARNING_RE = re.compile(r'^\s*(!|\[WARNING\]|Warning:)', re.I)
_SUGGESTION_START_RE = re.compile(r'^=+\s*Suggestions?\s*=+', re.I)
_SUGGESTION_ITEM_RE = re.compile(r'^\s*\*\s+(.+)$')


def _parse_lynis_score(raw: str) -> Optional[int]:
    m = _HARDENING_INDEX_RE.search(raw)
    return int(m.group(1)) if m else None


def _parse_lynis_warnings(raw: str) -> list[str]:
    return [
        line.strip()[:200]
        for line in raw.splitlines()
        if _WARNING_RE.match(line) and len(line.strip()) > 3
    ][:30]


def _parse_lynis_suggestions(raw: str) -> list[str]:
    suggestions: list[str] = []
    in_suggestions = False
    for line in raw.splitlines():
        if _SUGGESTION_START_RE.match(line):
            in_suggestions = True
            continue
        if in_suggestions:
            m = _SUGGESTION_ITEM_RE.match(line)
            if m:
                suggestions.append(m.group(1).strip()[:200])
    return suggestions[:25]


def _score_controls(profile: dict, warnings: list[str]) -> list[dict]:
    """Heuristically mark controls pass/fail based on warning text overlap."""
    results = []
    warnings_lower = " ".join(warnings).lower()
    for ctrl in profile["controls"]:
        # Extract meaningful words from control title
        words = [w for w in ctrl["title"].lower().split() if len(w) > 4]
        failed = any(w in warnings_lower for w in words)
        results.append({
            "id": ctrl["id"],
            "title": ctrl["title"],
            "status": "fail" if failed else "pass",
        })
    return results


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/profiles")
def list_profiles():
    return list(PROFILES.values())


@router.get("/profiles/{profile_id}")
def get_profile(profile_id: str):
    if profile_id not in PROFILES:
        raise HTTPException(404, "Profile not found")
    return PROFILES[profile_id]


class ScoreRequest(BaseModel):
    scan_id: str
    profile_id: str
    project_id: str


@router.post("/score")
def score_scan(req: ScoreRequest, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == req.scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    if not scan.raw_output:
        raise HTTPException(400, "Scan has no output yet — run the audit first.")

    profile = PROFILES.get(req.profile_id)
    if not profile:
        raise HTTPException(404, "Profile not found")

    raw = scan.raw_output
    hardening_index = _parse_lynis_score(raw)
    warnings = _parse_lynis_warnings(raw)
    suggestions = _parse_lynis_suggestions(raw)
    controls = _score_controls(profile, warnings)

    # Derive overall score
    if hardening_index is not None:
        overall_score = hardening_index          # lynis hardening index (authoritative)
    elif warnings or suggestions:
        # lynis-style output without an explicit index — estimate from warnings/fails
        fail_count = sum(1 for c in controls if c["status"] == "fail")
        overall_score = min(max(5, 65 - fail_count * 4 - len(warnings)), 95)
    else:
        # Non-lynis hardening scan (e.g. CIS-CAT / openscap / any audit) — derive a
        # severity-weighted posture score from this scan's open findings.
        from database import Finding
        sev_weight = {"critical": 25, "high": 12, "medium": 5, "low": 1, "info": 0}
        scan_findings = db.query(Finding).filter(Finding.scan_id == req.scan_id).all()
        open_findings = [f for f in scan_findings if (f.status or "open") in ("open", "in-review")]
        penalty = sum(sev_weight.get(f.severity, 3) for f in open_findings)
        overall_score = max(0, 100 - penalty)
        controls = [
            {"control": (f.control_id or f.title or "")[:80], "status": "fail", "severity": f.severity}
            for f in open_findings[:100]
        ]

    controls_data = {
        "controls": controls,
        "warnings": warnings,
        "suggestions": suggestions,
    }

    existing = db.query(HardeningReport).filter(
        HardeningReport.scan_id == req.scan_id,
        HardeningReport.profile == req.profile_id,
    ).first()

    if existing:
        existing.overall_score = str(overall_score)
        existing.controls_json = json.dumps(controls_data)
        db.commit()
        report = existing
    else:
        report = HardeningReport(
            id=str(uuid.uuid4()),
            project_id=req.project_id,
            target_id=scan.target_id,
            profile=req.profile_id,
            overall_score=str(overall_score),
            controls_json=json.dumps(controls_data),
            scan_id=req.scan_id,
        )
        db.add(report)
        db.commit()
        db.refresh(report)

    pass_count = sum(1 for c in controls if c["status"] == "pass")
    fail_count = sum(1 for c in controls if c["status"] == "fail")

    return {
        "id": report.id,
        "profile_id": req.profile_id,
        "profile": profile["name"],
        "overall_score": overall_score,
        "controls": controls,
        "warnings": warnings,
        "suggestions": suggestions,
        "pass_count": pass_count,
        "fail_count": fail_count,
    }


@router.get("/reports")
def list_reports(project_id: str, db: Session = Depends(get_db)):
    reports = (
        db.query(HardeningReport)
        .filter(HardeningReport.project_id == project_id)
        .order_by(HardeningReport.created_at.desc())
        .all()
    )
    result = []
    for r in reports:
        controls_data = json.loads(r.controls_json or "{}")
        controls = controls_data.get("controls", [])
        result.append({
            "id": r.id,
            "profile": PROFILES.get(r.profile, {}).get("name", r.profile),
            "profile_id": r.profile,
            "overall_score": int(r.overall_score or 0),
            "pass_count": sum(1 for c in controls if c.get("status") == "pass"),
            "fail_count": sum(1 for c in controls if c.get("status") == "fail"),
            "scan_id": r.scan_id,
            "target_id": r.target_id,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        })
    return result


@router.get("/reports/{report_id}")
def get_report(report_id: str, db: Session = Depends(get_db)):
    report = db.query(HardeningReport).filter(HardeningReport.id == report_id).first()
    if not report:
        raise HTTPException(404, "Report not found")
    controls_data = json.loads(report.controls_json or "{}")
    profile_info = PROFILES.get(report.profile, {})
    return {
        "id": report.id,
        "profile": profile_info.get("name", report.profile),
        "profile_id": report.profile,
        "overall_score": int(report.overall_score or 0),
        "controls": controls_data.get("controls", []),
        "warnings": controls_data.get("warnings", []),
        "suggestions": controls_data.get("suggestions", []),
        "scan_id": report.scan_id,
        "target_id": report.target_id,
        "created_at": report.created_at.isoformat() if report.created_at else None,
    }
