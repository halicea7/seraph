import asyncio
import re
import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from database import ADCollection, C2Session, Credential, Finding, FPSuppressionRule, HttpRequestItem, Project, Scan, Screenshot, Target, VulnerabilityRecord, get_db
from services.scope_service import check_scope, scope_summary
from services.validators import (
    VALID_TARGET_TYPES,
    validate_free_text,
    validate_hostname_or_ip,
)

router = APIRouter(prefix="/projects", tags=["projects"])

# Keep local alias for pattern used in existing validators below
import re as _re
HOSTNAME_IP_PATTERN = _re.compile(
    r"^(?:"
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"|"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r")$"
)


# ── Pydantic schemas ──────────────────────────────────────────────────────────


class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: str) -> str:
        return validate_free_text(v.strip(), max_length=256, field_name="name")

    @field_validator("description")
    @classmethod
    def _check_description(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return validate_free_text(v, max_length=2048, field_name="description")


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return validate_free_text(v.strip(), max_length=256, field_name="name")

    @field_validator("description")
    @classmethod
    def _check_description(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return validate_free_text(v, max_length=2048, field_name="description")


class ScopeUpdate(BaseModel):
    include: List[str] = []
    exclude: List[str] = []


class ProjectResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    created_at: datetime
    target_count: int = 0
    finding_count: int = 0
    latest_finding_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class TargetCreate(BaseModel):
    hostname_or_ip: str
    target_type: str
    ports: Optional[str] = None
    notes: Optional[str] = None

    @field_validator("hostname_or_ip")
    @classmethod
    def validate_hostname_or_ip(cls, v: str) -> str:
        if not HOSTNAME_IP_PATTERN.match(v):
            raise ValueError(
                "hostname_or_ip must be a valid IP address or hostname"
            )
        return v

    @field_validator("target_type")
    @classmethod
    def validate_target_type(cls, v: str) -> str:
        if v not in VALID_TARGET_TYPES:
            raise ValueError(
                f"target_type must be one of: {', '.join(sorted(VALID_TARGET_TYPES))}"
            )
        return v


class TargetUpdate(BaseModel):
    hostname_or_ip: Optional[str] = None
    target_type: Optional[str] = None
    ports: Optional[str] = None
    notes: Optional[str] = None

    @field_validator("hostname_or_ip")
    @classmethod
    def validate_hostname_or_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not HOSTNAME_IP_PATTERN.match(v):
            raise ValueError(
                "hostname_or_ip must be a valid IP address or hostname"
            )
        return v

    @field_validator("target_type")
    @classmethod
    def validate_target_type(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in VALID_TARGET_TYPES:
            raise ValueError(
                f"target_type must be one of: {', '.join(sorted(VALID_TARGET_TYPES))}"
            )
        return v


class ScanSummary(BaseModel):
    id: str
    scan_type: str
    module: str
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class TargetResponse(BaseModel):
    id: str
    project_id: str
    hostname_or_ip: str
    target_type: str
    ports: Optional[str]
    notes: Optional[str]
    created_at: datetime
    scans: List[ScanSummary] = []

    class Config:
        from_attributes = True


class TargetSummary(BaseModel):
    id: str
    project_id: str
    hostname_or_ip: str
    target_type: str
    ports: Optional[str]
    notes: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class ProjectDetail(BaseModel):
    id: str
    name: str
    description: Optional[str]
    created_at: datetime
    targets: List[TargetSummary] = []

    class Config:
        from_attributes = True


# ── Project endpoints ─────────────────────────────────────────────────────────


@router.get("", response_model=List[ProjectResponse])
def list_projects(db: Session = Depends(get_db)):
    from sqlalchemy import func
    projects = db.query(Project).order_by(Project.created_at.desc()).all()

    # Build target_id → project_id map for a single bulk findings query
    all_targets = db.query(Target.id, Target.project_id).all()
    target_to_project = {t.id: t.project_id for t in all_targets}

    # Aggregate finding counts + latest per project via scan → target chain
    scan_rows = db.query(Scan.id, Scan.target_id).all()
    scan_to_target = {s.id: s.target_id for s in scan_rows}

    finding_agg = db.query(
        Finding.scan_id,
        func.count(Finding.id).label("cnt"),
        func.max(Finding.created_at).label("latest"),
    ).group_by(Finding.scan_id).all()

    proj_counts: dict = {}
    proj_latest: dict = {}
    for row in finding_agg:
        target_id = scan_to_target.get(row.scan_id)
        if not target_id:
            continue
        proj_id = target_to_project.get(target_id)
        if not proj_id:
            continue
        proj_counts[proj_id] = proj_counts.get(proj_id, 0) + row.cnt
        if row.latest:
            if proj_id not in proj_latest or row.latest > proj_latest[proj_id]:
                proj_latest[proj_id] = row.latest

    result = []
    for p in projects:
        result.append(
            ProjectResponse(
                id=p.id,
                name=p.name,
                description=p.description,
                created_at=p.created_at,
                target_count=len(p.targets),
                finding_count=proj_counts.get(p.id, 0),
                latest_finding_at=proj_latest.get(p.id),
            )
        )
    return result


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)):
    project = Project(
        id=str(uuid.uuid4()),
        name=payload.name,
        description=payload.description,
        created_at=datetime.utcnow(),
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        created_at=project.created_at,
        target_count=0,
    )


@router.get("/{project_id}", response_model=ProjectDetail)
def get_project(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.put("/{project_id}", response_model=ProjectResponse)
def update_project(
    project_id: str, payload: ProjectUpdate, db: Session = Depends(get_db)
):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if payload.name is not None:
        project.name = payload.name
    if payload.description is not None:
        project.description = payload.description
    db.commit()
    db.refresh(project)
    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        created_at=project.created_at,
        target_count=len(project.targets),
    )


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    # VulnerabilityRecord, Credential, and ADCollection have project_id FKs without cascade
    db.query(VulnerabilityRecord).filter(VulnerabilityRecord.project_id == project_id).delete()
    db.query(Credential).filter(Credential.project_id == project_id).delete()
    db.query(ADCollection).filter(ADCollection.project_id == project_id).delete()
    db.query(Screenshot).filter(Screenshot.project_id == project_id).delete()
    db.query(HttpRequestItem).filter(HttpRequestItem.project_id == project_id).delete()
    db.delete(project)
    db.commit()


@router.get("/{project_id}/scratchpad")
def get_scratchpad(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return {"content": project.scratchpad or ""}


@router.put("/{project_id}/scratchpad")
def save_scratchpad(project_id: str, payload: dict, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    project.scratchpad = payload.get("content", "")
    db.commit()
    return {"content": project.scratchpad}


@router.get("/{project_id}/scans")
def get_project_scans(project_id: str, db: Session = Depends(get_db)):
    """Get all scans for a project (across all targets)."""
    targets = db.query(Target).filter(Target.project_id == project_id).all()
    target_ids = [t.id for t in targets]
    if not target_ids:
        return []
    scans = db.query(Scan).filter(Scan.target_id.in_(target_ids)).order_by(Scan.id.desc()).all()
    result = []
    for s in scans:
        target = next((t for t in targets if t.id == s.target_id), None)
        finding_count = db.query(Finding).filter(Finding.scan_id == s.id).count()
        result.append({
            "id": s.id,
            "scan_type": s.scan_type,
            "module": s.module,
            "status": s.status,
            "target": target.hostname_or_ip if target else "unknown",
            "started_at": str(s.started_at) if s.started_at else None,
            "completed_at": str(s.completed_at) if s.completed_at else None,
            "finding_count": finding_count,
        })
    return result


@router.get("/{project_id}/phases")
def get_project_phases(project_id: str, db: Session = Depends(get_db)):
    """Derive engagement phase status from the project's actual scan records."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    targets = db.query(Target).filter(Target.project_id == project_id).all()
    target_ids = [t.id for t in targets]
    scans = (
        db.query(Scan).filter(Scan.target_id.in_(target_ids)).all()
        if target_ids else []
    )

    phase_defs = [
        ("recon",       "Recon",       {"nmap", "whois", "subfinder", "theharvester", "amass"}),
        ("enum",        "Enumeration", {"nikto", "gobuster", "whatweb", "enum4linux", "crackmapexec", "wfuzz", "kerberoast", "asreproast"}),
        ("exploit",     "Exploit",     {"sqlmap", "searchsploit", "nessus_import"}),
        ("post_exploit","Post-Exploit",{"postex"}),
    ]

    result = []
    for phase_id, phase_name, phase_types in phase_defs:
        phase_scans = [
            s for s in scans
            if s.scan_type.lower() in phase_types
            or (phase_id == "exploit" and s.scan_type.lower().startswith("msf"))
        ]
        tools_used = sorted({s.scan_type for s in phase_scans})
        completed = [s for s in phase_scans if s.status == "completed"]
        active    = [s for s in phase_scans if s.status in ("running", "pending")]

        if active:
            phase_status = "running"
            progress = int(len(completed) / len(phase_scans) * 100) if phase_scans else 0
        elif completed:
            phase_status = "done"
            progress = 100
        else:
            phase_status = "pending"
            progress = 0

        first_started = min(
            (s.started_at for s in phase_scans if s.started_at), default=None
        )
        last_ended = max(
            (s.completed_at for s in completed if s.completed_at), default=None
        ) if phase_status == "done" else None

        result.append({
            "id": phase_id,
            "name": phase_name,
            "status": phase_status,
            "tools": tools_used if tools_used else list(sorted(phase_types))[:2],
            "started": first_started.isoformat() if first_started else None,
            "ended": last_ended.isoformat() if last_ended else None,
            "progress": progress,
        })

    return result


# ── Target endpoints (nested under /projects/{id}/targets) ───────────────────


@router.get("/{project_id}/targets", response_model=List[TargetSummary])
def list_targets(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project.targets


@router.post(
    "/{project_id}/targets",
    response_model=TargetSummary,
    status_code=status.HTTP_201_CREATED,
)
async def create_target(
    project_id: str, payload: TargetCreate, db: Session = Depends(get_db)
):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    in_scope, reason = check_scope(payload.hostname_or_ip, getattr(project, "scope_json", None))
    if not in_scope:
        raise HTTPException(status_code=400, detail=f"Target out of scope: {reason}")

    target = Target(
        id=str(uuid.uuid4()),
        project_id=project_id,
        hostname_or_ip=payload.hostname_or_ip,
        target_type=payload.target_type,
        ports=payload.ports,
        notes=payload.notes,
        created_at=datetime.utcnow(),
    )
    db.add(target)
    db.commit()
    db.refresh(target)

    # Fire auto-probe in the background — safe because this is an async endpoint
    from services.auto_probe import run_auto_probe, get_probe_config
    config = get_probe_config()
    if config["enabled"]:
        asyncio.create_task(
            run_auto_probe(target.id, target.hostname_or_ip, config["tools"], config["intensity"])
        )

    return target


@router.get("/{project_id}/scope")
def get_scope(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return scope_summary(getattr(project, "scope_json", None))


@router.put("/{project_id}/scope")
def update_scope(project_id: str, payload: ScopeUpdate, db: Session = Depends(get_db)):
    import json as _json
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    project.scope_json = _json.dumps({"include": payload.include, "exclude": payload.exclude})
    db.commit()
    return scope_summary(project.scope_json)


@router.get("/{project_id}/targets/{target_id}/probe-status")
def get_probe_status(project_id: str, target_id: str, db: Session = Depends(get_db)):
    """Returns auto-probe scan status for a target."""
    import json as _json
    scans = db.query(Scan).filter(Scan.target_id == target_id).all()
    probe_scans = []
    for s in scans:
        try:
            cfg = _json.loads(s.config_json or "{}")
        except Exception:
            cfg = {}
        if cfg.get("auto_probe"):
            probe_scans.append({
                "id": s.id,
                "tool": cfg.get("tool", s.scan_type),
                "scan_type": s.scan_type,
                "status": s.status,
                "started_at": str(s.started_at) if s.started_at else None,
                "completed_at": str(s.completed_at) if s.completed_at else None,
            })
    running = any(s["status"] in ("pending", "running") for s in probe_scans)
    return {"running": running, "scans": probe_scans}


# ── Stats endpoint ────────────────────────────────────────────────────────────

stats_router = APIRouter(tags=["stats"])


@stats_router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """Return overall platform statistics."""
    from sqlalchemy import func

    project_count = db.query(Project).count()
    target_count = db.query(Target).count()
    scan_count = db.query(Scan).count()
    finding_count = db.query(Finding).count()

    # Findings by severity
    severity_counts = dict(
        db.query(Finding.severity, func.count(Finding.id))
        .group_by(Finding.severity)
        .all()
    )

    # Recent scans — preload targets to avoid N+1
    import json as _json
    recent_scans_raw = db.query(Scan).order_by(Scan.created_at.desc()).limit(10).all()
    _target_ids = {s.target_id for s in recent_scans_raw}
    _targets_map = {t.id: t for t in db.query(Target).filter(Target.id.in_(_target_ids)).all()}
    recent_data = []
    for s in recent_scans_raw:
        target = _targets_map.get(s.target_id)
        try:
            cfg = _json.loads(s.config_json or "{}")
        except Exception:
            cfg = {}
        recent_data.append({
            "id": s.id,
            "scan_type": s.scan_type,
            "status": s.status,
            "target": target.hostname_or_ip if target else "unknown",
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "auto_probe": cfg.get("auto_probe", False),
        })

    # Recent findings — preload scans/targets/projects to avoid N+1
    recent_findings_raw = (
        db.query(Finding)
        .order_by(Finding.created_at.desc())
        .limit(20)
        .all()
    )
    _scan_ids = {f.scan_id for f in recent_findings_raw}
    _scans_map = {s.id: s for s in db.query(Scan).filter(Scan.id.in_(_scan_ids)).all()}
    _target_ids2 = {s.target_id for s in _scans_map.values()}
    _targets_map2 = {t.id: t for t in db.query(Target).filter(Target.id.in_(_target_ids2)).all()}
    _project_ids = {t.project_id for t in _targets_map2.values()}
    _projects_map = {p.id: p for p in db.query(Project).filter(Project.id.in_(_project_ids)).all()}
    recent_findings = []
    for f in recent_findings_raw:
        scan = _scans_map.get(f.scan_id)
        target = _targets_map2.get(scan.target_id) if scan else None
        project = _projects_map.get(target.project_id) if target else None
        recent_findings.append({
            "id": f.id,
            "severity": f.severity,
            "title": f.title,
            "cve_id": f.cve_id,
            "cvss_score": f.cvss_score,
            "target": target.hostname_or_ip if target else "unknown",
            "project": project.name if project else "unknown",
            "created_at": f.created_at.isoformat() if f.created_at else None,
        })

    return {
        "projects": project_count,
        "targets": target_count,
        "scans": scan_count,
        "findings": finding_count,
        "severity_counts": severity_counts,
        "recent_scans": recent_data,
        "recent_findings": recent_findings,
    }


@stats_router.get("/stats/history")
def get_stats_history(days: int = 14, db: Session = Depends(get_db)):
    """Return per-day finding counts grouped by severity for the last N days."""
    from datetime import timedelta
    from sqlalchemy import func, cast, Date

    cutoff = datetime.utcnow() - timedelta(days=days)
    rows = (
        db.query(
            func.strftime("%Y-%m-%d", Finding.created_at).label("day"),
            Finding.severity,
            func.count(Finding.id).label("count"),
        )
        .filter(Finding.created_at >= cutoff)
        .group_by("day", Finding.severity)
        .order_by("day")
        .all()
    )

    # Build a list of date strings covering the full range
    today = datetime.utcnow().date()
    date_range = [(today - timedelta(days=days - 1 - i)).isoformat() for i in range(days)]

    # Pivot into {date: {severity: count}}
    pivot: dict = {d: {} for d in date_range}
    for row in rows:
        if row.day in pivot:
            pivot[row.day][row.severity] = row.count

    return {"days": date_range, "pivot": pivot}


@stats_router.get("/stats/posture")
def get_posture_history(project_id: str, days: int = 90, db: Session = Depends(get_db)):
    """Per-day posture trend for one project: new findings by severity, the cumulative
    trajectory, and coverage drift (distinct controls touched over time).

    Derived from finding created_at — we don't track status-change history, so this is
    finding *influx* and cumulative totals, not an open/closed stock over time.
    """
    from datetime import timedelta

    days = max(7, min(days, 365))
    sevs = ["critical", "high", "medium", "low", "info"]

    target_ids = [t.id for t in db.query(Target).filter(Target.project_id == project_id).all()]
    findings = []
    if target_ids:
        scan_ids = [s.id for s in db.query(Scan).filter(Scan.target_id.in_(target_ids)).all()]
        if scan_ids:
            findings = db.query(Finding).filter(Finding.scan_id.in_(scan_ids)).order_by(Finding.created_at).all()

    today = datetime.utcnow().date()
    start = today - timedelta(days=days - 1)
    start_iso = start.isoformat()
    dates = [(start + timedelta(days=i)).isoformat() for i in range(days)]

    per_day = {d: {s: 0 for s in sevs} for d in dates}
    controls_by_day = {d: set() for d in dates}
    cum_before = {s: 0 for s in sevs}          # findings before the window
    controls_before: set = set()

    for f in findings:
        if not f.created_at:
            continue
        d = f.created_at.date().isoformat()
        ckey = f"{f.framework or ''}|{f.control_id or ''}" if (f.framework or f.control_id) else None
        if d < start_iso:
            if f.severity in cum_before:
                cum_before[f.severity] += 1
            if ckey:
                controls_before.add(ckey)
            continue
        if d in per_day:
            if f.severity in per_day[d]:
                per_day[d][f.severity] += 1
            if ckey:
                controls_by_day[d].add(ckey)

    series = []
    cum = dict(cum_before)
    cum_controls = set(controls_before)
    for d in dates:
        for s in sevs:
            cum[s] += per_day[d][s]
        cum_controls |= controls_by_day[d]
        series.append({
            "date": d,
            "new": per_day[d],
            "new_total": sum(per_day[d].values()),
            "cumulative": dict(cum),
            "cumulative_total": sum(cum.values()),
            "controls_total": len(cum_controls),
        })

    return {"project_id": project_id, "days": days, "series": series}


@stats_router.get("/findings")
def list_findings(
    severity: Optional[str] = None,
    project_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """All findings with project/target context, optionally filtered."""
    from sqlalchemy import func as _func

    # Build filtered query at the DB level
    query = db.query(Finding).order_by(Finding.created_at.desc())
    if severity:
        query = query.filter(Finding.severity == severity)
    findings = query.all()

    # Preload related rows to avoid N+1
    scan_ids = {f.scan_id for f in findings}
    scans_map = {s.id: s for s in db.query(Scan).filter(Scan.id.in_(scan_ids)).all()}
    target_ids = {s.target_id for s in scans_map.values()}
    targets_map = {t.id: t for t in db.query(Target).filter(Target.id.in_(target_ids)).all()}
    project_ids = {t.project_id for t in targets_map.values()}
    projects_map = {p.id: p for p in db.query(Project).filter(Project.id.in_(project_ids)).all()}

    result = []
    for f in findings:
        scan = scans_map.get(f.scan_id)
        target = targets_map.get(scan.target_id) if scan else None
        project = projects_map.get(target.project_id) if target else None
        if project_id and (not project or project.id != project_id):
            continue
        result.append({
            "id": f.id,
            "severity": f.severity,
            "title": f.title,
            "description": f.description,
            "remediation": f.remediation,
            "cve_id": f.cve_id,
            "cvss_score": f.cvss_score,
            "status": getattr(f, "status", "open") or "open",
            "fp_reason": getattr(f, "fp_reason", None),
            "tags": getattr(f, "tags", "") or "",
            "target": target.hostname_or_ip if target else "unknown",
            "project": project.name if project else "unknown",
            "project_id": project.id if project else None,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        })
    return result


_SLA_DEFAULTS = {"critical": 7, "high": 14, "medium": 30, "low": 90, "info": None}
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _normalize_title(t: str) -> str:
    return re.sub(r"\s+", " ", (t or "").lower().strip())


def _finding_fingerprint(f: Finding, target_id: str) -> str:
    return f"{target_id or '?'}|{(f.cve_id or '').upper()}|{f.control_id or ''}|{_normalize_title(f.title)}"


def _sla_days(db: Session) -> dict:
    from database import AppSetting
    out = dict(_SLA_DEFAULTS)
    for sev in list(out.keys()):
        row = db.query(AppSetting).filter(AppSetting.key == f"sla_days_{sev}").first()
        if row and row.value not in (None, ""):
            try:
                out[sev] = int(row.value)
            except ValueError:
                pass
    return out


@stats_router.get("/findings/sla-config")
def get_sla_config(db: Session = Depends(get_db)):
    return _sla_days(db)


@stats_router.put("/findings/sla-config")
def set_sla_config(payload: dict, db: Session = Depends(get_db)):
    from database import AppSetting
    for sev in _SLA_DEFAULTS:
        if sev not in payload:
            continue
        val = payload[sev]
        sval = "" if val in (None, "") else str(int(val))
        row = db.query(AppSetting).filter(AppSetting.key == f"sla_days_{sev}").first()
        if row:
            row.value = sval
        else:
            db.add(AppSetting(key=f"sla_days_{sev}", value=sval))
    db.commit()
    return _sla_days(db)


@stats_router.get("/findings/grouped")
def list_findings_grouped(project_id: Optional[str] = None, db: Session = Depends(get_db)):
    """Findings deduplicated by fingerprint (target + cve/control + normalized title),
    with occurrences, first/last seen, and SLA due/overdue.

    Read-time dedup only — the underlying per-scan Finding rows are untouched, so
    ScanDiff and per-scan finding views keep working.
    """
    from datetime import datetime, timedelta

    findings = db.query(Finding).order_by(Finding.created_at.desc()).all()
    scans_map = {s.id: s for s in db.query(Scan).filter(Scan.id.in_({f.scan_id for f in findings})).all()}
    targets_map = {t.id: t for t in db.query(Target).filter(Target.id.in_({s.target_id for s in scans_map.values()})).all()}
    projects_map = {p.id: p for p in db.query(Project).filter(Project.id.in_({t.project_id for t in targets_map.values()})).all()}

    groups: dict[str, dict] = {}
    for f in findings:
        scan = scans_map.get(f.scan_id)
        target = targets_map.get(scan.target_id) if scan else None
        project = projects_map.get(target.project_id) if target else None
        if project_id and (not project or project.id != project_id):
            continue
        fp = _finding_fingerprint(f, target.id if target else "?")
        g = groups.get(fp)
        if not g:
            groups[fp] = g = {
                "id": f.id,  # representative = latest (rows are ordered created_at desc)
                "severity": f.severity, "title": f.title, "description": f.description,
                "remediation": f.remediation, "cve_id": f.cve_id, "cvss_score": f.cvss_score,
                "control_id": f.control_id, "framework": f.framework, "evidence": f.evidence,
                "status": getattr(f, "status", "open") or "open",
                "tags": getattr(f, "tags", "") or "",
                "target": target.hostname_or_ip if target else "unknown",
                "project": project.name if project else "unknown",
                "project_id": project.id if project else None,
                "occurrences": 0, "first_seen": f.created_at, "last_seen": f.created_at,
                "scan_ids": set(),
            }
        g["occurrences"] += 1
        if f.scan_id:
            g["scan_ids"].add(f.scan_id)
        if f.created_at:
            g["first_seen"] = min(g["first_seen"] or f.created_at, f.created_at)
            g["last_seen"] = max(g["last_seen"] or f.created_at, f.created_at)

    sla = _sla_days(db)
    now = datetime.utcnow()
    still_open = {"open", "in-review"}
    result = []
    for g in groups.values():
        days = sla.get(g["severity"])
        due = (g["first_seen"] + timedelta(days=days)) if (days and g["first_seen"]) else None
        overdue = bool(due and g["status"] in still_open and now > due)
        item = {k: v for k, v in g.items() if k not in ("first_seen", "last_seen", "scan_ids")}
        item.update({
            "first_seen": g["first_seen"].isoformat() if g["first_seen"] else None,
            "last_seen": g["last_seen"].isoformat() if g["last_seen"] else None,
            "scan_ids": sorted(g["scan_ids"]),
            "sla_due": due.isoformat() if due else None,
            "overdue": overdue,
        })
        result.append(item)

    result.sort(key=lambda x: (x["overdue"], _SEV_RANK.get(x["severity"], 0), x["last_seen"] or ""), reverse=True)
    return {"sla_days": sla, "findings": result}


@stats_router.post("/findings/{finding_id}/retest")
def retest_finding(finding_id: str, db: Session = Depends(get_db)):
    """Clone the finding's originating audit scan so it can be re-run to verify a fix.

    Returns a fresh scan + regenerated script; the caller runs it over /ws/execute
    (which auto-parses), then calls /retest/evaluate to record the verdict.
    """
    import json as _json
    from services.script_generator import generate_script

    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    scan = db.query(Scan).filter(Scan.id == f.scan_id).first()
    if not scan or scan.module != "audit" or not scan.config_json:
        raise HTTPException(status_code=400, detail="Only audit findings can be auto-retested")
    config = _json.loads(scan.config_json)
    categories = config.get("categories")
    if not categories:
        raise HTTPException(status_code=400, detail="Originating scan has no reproducible config")
    target = db.query(Target).filter(Target.id == scan.target_id).first()
    project = db.query(Project).filter(Project.id == target.project_id).first() if target else None
    if not target or not project:
        raise HTTPException(status_code=404, detail="Target or project not found")

    script = generate_script(project_name=project.name, target=target.hostname_or_ip, scan_categories=categories)
    new = Scan(id=str(uuid.uuid4()), target_id=scan.target_id, scan_type=scan.scan_type,
               module="audit", status="pending", config_json=scan.config_json)
    db.add(new)
    db.commit()
    db.refresh(new)
    return {"scan_id": new.id, "script": script, "uses_ssh": bool(config.get("credential_id"))}


@stats_router.post("/findings/{finding_id}/retest/evaluate")
def evaluate_retest(finding_id: str, payload: dict, db: Session = Depends(get_db)):
    """After a retest scan has run, check whether the finding reappeared. If it's gone,
    mark the original finding remediated."""
    new_scan_id = str(payload.get("scan_id", ""))
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    orig = db.query(Scan).filter(Scan.id == f.scan_id).first()
    target_id = orig.target_id if orig else "?"
    fp = _finding_fingerprint(f, target_id)
    new_findings = db.query(Finding).filter(Finding.scan_id == new_scan_id).all()
    present = any(_finding_fingerprint(nf, target_id) == fp for nf in new_findings)
    if not present and f.status in ("open", "in-review"):
        f.status = "remediated"
        db.commit()
    return {"still_present": present, "status": f.status, "checked": len(new_findings)}


@stats_router.patch("/findings/{finding_id}/status")
def update_finding_status(finding_id: str, payload: dict, db: Session = Depends(get_db)):
    valid = {"open", "in-review", "remediated", "accepted", "false_positive"}
    new_status = payload.get("status", "")
    if new_status not in valid:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=f"status must be one of {valid}")
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Finding not found")
    f.status = new_status
    db.commit()
    return {"id": finding_id, "status": new_status}


@stats_router.post("/findings/{finding_id}/ai-remediate")
def ai_remediate_finding(finding_id: str, db: Session = Depends(get_db)):
    """AI-generated remediation guidance for a scan finding (server-configured model).
    Mirrors /vulns/{id}/ai-remediate; returns the text (not persisted)."""
    from services.ai_client import chat_complete, load_llm_params
    from database import AppSetting

    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")

    def _g(key: str, default: str = "") -> str:
        row = db.query(AppSetting).filter(AppSetting.key == key).first()
        return row.value if row else default

    endpoint = _g("ai_endpoint", "http://localhost:11434")
    model = _g("ai_model", "")
    if not model:
        raise HTTPException(status_code=400, detail="No AI model configured. Go to Settings → AI to set one.")

    prompt = (
        "You are a cybersecurity engineer providing remediation guidance.\n\n"
        f"Finding: {f.title}\n"
        f"Severity: {(f.severity or '').upper()}\n"
        f"CVE: {f.cve_id or 'N/A'}   CVSS: {f.cvss_score or 'N/A'}\n"
        f"Framework/Control: {(f.framework or '-')} {f.control_id or ''}\n"
        f"Description: {(f.description or 'No description provided.')[:600]}\n"
        f"Evidence: {(f.evidence or '')[:400]}\n\n"
        "Provide specific, actionable remediation: 1) immediate mitigations, 2) the long-term fix "
        "with concrete commands/config, 3) verification steps. Be concise and technical; numbered steps."
    )
    try:
        result = chat_complete(endpoint, model, [{"role": "user", "content": prompt}], **load_llm_params(db))
        return {"ai_remediation": result}
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@stats_router.post("/findings/{finding_id}/suppress")
def suppress_finding(finding_id: str, payload: dict, db: Session = Depends(get_db)):
    """Mark a finding as a false positive with a mandatory reason."""
    reason = str(payload.get("reason", "")).strip()
    if not reason:
        raise HTTPException(status_code=400, detail="A reason is required to suppress a finding as false positive")
    if len(reason) > 1000:
        raise HTTPException(status_code=400, detail="Reason too long (max 1000 chars)")
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    f.status = "false_positive"
    f.fp_reason = reason
    db.commit()
    return {"id": finding_id, "status": "false_positive", "fp_reason": reason}


@stats_router.post("/findings/{finding_id}/restore")
def restore_finding(finding_id: str, db: Session = Depends(get_db)):
    """Restore a suppressed finding back to 'open' status."""
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    f.status = "open"
    f.fp_reason = None
    db.commit()
    return {"id": finding_id, "status": "open"}


@stats_router.patch("/findings/{finding_id}/tags")
def update_finding_tags(finding_id: str, payload: dict, db: Session = Depends(get_db)):
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Finding not found")
    tags = [t.strip() for t in payload.get("tags", []) if t.strip()]
    f.tags = ",".join(tags)
    db.commit()
    return {"id": finding_id, "tags": f.tags}


@stats_router.get("/findings/{finding_id}/exploit-chain")
def get_exploit_chain(finding_id: str, db: Session = Depends(get_db)):
    """Return the exploit chain for a finding (linked sessions + lateral moves)."""
    import json as _json
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        from fastapi import HTTPException
        raise HTTPException(404, "Finding not found")
    chain = _json.loads(f.exploit_chain_json or "[]")
    # Enrich with session details
    enriched = []
    for step in chain:
        entry = dict(step)
        if step.get("session_id"):
            sess = db.query(C2Session).filter(C2Session.id == step["session_id"]).first()
            if sess:
                entry["session"] = {
                    "remote_host": sess.remote_host,
                    "platform": sess.platform,
                    "session_type": sess.session_type,
                    "status": sess.status,
                }
        enriched.append(entry)
    return {"finding_id": finding_id, "chain": enriched}


@stats_router.post("/findings/{finding_id}/exploit-chain")
def add_exploit_chain_step(finding_id: str, payload: dict, db: Session = Depends(get_db)):
    """Link a C2 session to a finding as an exploit chain step."""
    import json as _json
    from datetime import datetime as _dt
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        from fastapi import HTTPException
        raise HTTPException(404, "Finding not found")
    session_id = payload.get("session_id")
    technique = str(payload.get("technique", "exploit"))[:200]
    notes = str(payload.get("notes", ""))[:500]
    if session_id:
        sess = db.query(C2Session).filter(C2Session.id == session_id).first()
        if not sess:
            from fastapi import HTTPException
            raise HTTPException(404, "Session not found")
        # Back-link the session to this finding
        sess.finding_id = finding_id
    chain = _json.loads(f.exploit_chain_json or "[]")
    chain.append({
        "session_id": session_id,
        "technique": technique,
        "notes": notes,
        "timestamp": _dt.utcnow().isoformat(),
    })
    f.exploit_chain_json = _json.dumps(chain)
    db.commit()
    return {"finding_id": finding_id, "chain": chain}


@stats_router.delete("/findings/{finding_id}/exploit-chain")
def clear_exploit_chain(finding_id: str, db: Session = Depends(get_db)):
    """Clear the exploit chain for a finding."""
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        from fastapi import HTTPException
        raise HTTPException(404, "Finding not found")
    f.exploit_chain_json = "[]"
    db.commit()
    return {"finding_id": finding_id, "chain": []}


@stats_router.get("/scans")
def list_scans(
    status: Optional[str] = None,
    project_id: Optional[str] = None,
    target_id: Optional[str] = None,
    module: Optional[str] = None,
    limit: int = 200,
    db: Session = Depends(get_db),
):
    """All scans with project/target context, optionally filtered."""
    import json as _json
    from sqlalchemy import func as _func

    # Build filtered query at the DB level
    query = db.query(Scan).order_by(Scan.created_at.desc())
    if status:
        query = query.filter(Scan.status == status)
    if target_id:
        query = query.filter(Scan.target_id == target_id)
    if module:
        query = query.filter(Scan.module == module)
    query = query.limit(limit)
    scans = query.all()

    # Preload related rows to avoid N+1
    target_ids = {s.target_id for s in scans}
    targets_map = {t.id: t for t in db.query(Target).filter(Target.id.in_(target_ids)).all()}
    project_ids = {t.project_id for t in targets_map.values()}
    projects_map = {p.id: p for p in db.query(Project).filter(Project.id.in_(project_ids)).all()}

    # Preload finding counts per scan in one query
    scan_ids = [s.id for s in scans]
    from sqlalchemy import func
    finding_counts = dict(
        db.query(Finding.scan_id, func.count(Finding.id))
        .filter(Finding.scan_id.in_(scan_ids))
        .group_by(Finding.scan_id)
        .all()
    )

    result = []
    for s in scans:
        target = targets_map.get(s.target_id)
        project = projects_map.get(target.project_id) if target else None
        if project_id and (not project or project.id != project_id):
            continue
        try:
            cfg = _json.loads(s.config_json or "{}")
        except Exception:
            cfg = {}
        result.append({
            "id": s.id,
            "scan_type": s.scan_type,
            "status": s.status,
            "target": target.hostname_or_ip if target else "unknown",
            "target_id": target.id if target else None,
            "project": project.name if project else "unknown",
            "project_id": project.id if project else None,
            "finding_count": finding_counts.get(s.id, 0),
            "auto_probe": cfg.get("auto_probe", False),
            "nessus_scan_id": s.nessus_scan_id,
            "nessus_status": s.nessus_status,
            "nessus_progress": s.nessus_progress,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        })
    return result


@stats_router.delete("/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    from fastapi import HTTPException as _HTTPException
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise _HTTPException(404, "Scan not found")
    # Delete findings (and their notes) first
    from database import FindingNote
    finding_ids = [f.id for f in db.query(Finding).filter(Finding.scan_id == scan_id).all()]
    if finding_ids:
        db.query(FindingNote).filter(FindingNote.finding_id.in_(finding_ids)).delete(synchronize_session=False)
        db.query(Finding).filter(Finding.scan_id == scan_id).delete(synchronize_session=False)
    db.delete(scan)
    db.commit()


@stats_router.post("/scans/{scan_id}/cancel", status_code=200)
def cancel_scan(scan_id: str, db: Session = Depends(get_db)):
    from fastapi import HTTPException as _HTTPException
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise _HTTPException(404, "Scan not found")
    if scan.status not in ("running", "pending"):
        raise _HTTPException(400, f"Scan is already {scan.status}")
    # Terminate the running asyncio task + subprocess (auto-probe scans).
    try:
        from services.auto_probe import cancel_probe
        cancel_probe(scan_id)
    except Exception:
        pass
    from datetime import datetime as _dt
    scan.status = "cancelled"
    scan.completed_at = _dt.utcnow()
    db.commit()
    return {"status": "cancelled"}


@stats_router.get("/scans/diff")
def diff_scans(a: str, b: str, db: Session = Depends(get_db)):
    """Compare findings between two scans. Returns new, resolved, and unchanged buckets."""
    from fastapi import HTTPException as _HTTPException

    def _get_findings(scan_id: str):
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise _HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        return db.query(Finding).filter(Finding.scan_id == scan_id).all()

    findings_a = _get_findings(a)
    findings_b = _get_findings(b)

    def _key(f):
        return (f.title.strip().lower(), f.severity)

    map_a = {_key(f): f for f in findings_a}
    map_b = {_key(f): f for f in findings_b}

    def _serialize(f):
        return {
            "id": f.id,
            "severity": f.severity,
            "title": f.title,
            "description": f.description,
            "cve_id": f.cve_id,
            "cvss_score": f.cvss_score,
        }

    new_keys = set(map_b) - set(map_a)
    resolved_keys = set(map_a) - set(map_b)
    unchanged_keys = set(map_a) & set(map_b)

    return {
        "scan_a": a,
        "scan_b": b,
        "new":       [_serialize(map_b[k]) for k in new_keys],
        "resolved":  [_serialize(map_a[k]) for k in resolved_keys],
        "unchanged": [_serialize(map_a[k]) for k in unchanged_keys],
    }


# ── Activity feed endpoint ────────────────────────────────────────────────────


@stats_router.get("/activity")
def get_activity(project_id: Optional[str] = None, limit: int = 20, db: Session = Depends(get_db)):
    """Return a flat activity feed for the given project (scans + findings + sessions)."""
    if not project_id:
        return []

    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        return []

    targets = db.query(Target).filter(Target.project_id == project_id).all()
    target_map = {t.id: t.hostname_or_ip for t in targets}
    target_ids = list(target_map.keys())

    entries: list[dict] = []

    if target_ids:
        scans = db.query(Scan).filter(Scan.target_id.in_(target_ids)).all()
        for s in scans:
            host = target_map.get(s.target_id, "unknown")
            if s.completed_at:
                entries.append({
                    "id": f"scan-{s.id}",
                    "timestamp": s.completed_at.isoformat(),
                    "message": f"{s.scan_type} scan on {host} — {s.status}",
                    "kind": "scan",
                })
            elif s.started_at:
                entries.append({
                    "id": f"scan-{s.id}",
                    "timestamp": s.started_at.isoformat(),
                    "message": f"{s.scan_type} scan on {host} — {s.status}",
                    "kind": "scan",
                })

        scan_ids = [s.id for s in scans]
        if scan_ids:
            scan_ts_map = {s.id: (s.completed_at or s.started_at) for s in scans}
            scan_target_map = {s.id: target_map.get(s.target_id, "unknown") for s in scans}
            findings = db.query(Finding).filter(Finding.scan_id.in_(scan_ids)).all()
            for f in findings:
                ts = scan_ts_map.get(f.scan_id)
                if not ts:
                    continue
                sev = (f.severity or "info").upper()
                host = scan_target_map.get(f.scan_id, "unknown")
                entries.append({
                    "id": f"finding-{f.id}",
                    "timestamp": ts.isoformat(),
                    "message": f"{sev}: {f.title or 'Finding'} on {host}",
                    "kind": "finding",
                })

        sessions = db.query(C2Session).filter(C2Session.project_id == project_id).all()
        for s in sessions:
            if s.established_at:
                host = target_map.get(s.target_id, s.remote_host or "unknown")
                entries.append({
                    "id": f"session-{s.id}",
                    "timestamp": s.established_at.isoformat(),
                    "message": f"Session established: {host} ({s.session_type or 'unknown'})",
                    "kind": "session",
                })

    entries.sort(key=lambda e: e["timestamp"], reverse=True)
    return entries[:limit]


# ── Engagement timeline endpoint ─────────────────────────────────────────────


@router.get("/{project_id}/timeline")
def get_project_timeline(project_id: str, db: Session = Depends(get_db)):
    """
    Return a chronological list of engagement events for a project.
    Each event has: id, kind, title, target, severity (optional), status (optional), ts.
    """
    import json as _json
    from datetime import datetime as _dt

    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    targets = db.query(Target).filter(Target.project_id == project_id).all()
    target_map = {t.id: t.hostname_or_ip for t in targets}
    target_ids = list(target_map.keys())

    events: list[dict] = []

    # Project created
    if project.created_at:
        events.append({
            "id": f"proj-{project.id}",
            "kind": "project",
            "title": f"Project created: {project.name}",
            "target": None,
            "severity": None,
            "status": None,
            "ts": project.created_at.isoformat(),
        })

    # Target added events
    for t in targets:
        if t.created_at:
            events.append({
                "id": f"target-{t.id}",
                "kind": "target",
                "title": f"Target added: {t.hostname_or_ip}",
                "target": t.hostname_or_ip,
                "severity": None,
                "status": None,
                "ts": t.created_at.isoformat(),
            })

    if target_ids:
        # Scan start events
        scans = db.query(Scan).filter(Scan.target_id.in_(target_ids)).all()
        for s in scans:
            host = target_map.get(s.target_id, "unknown")
            if s.started_at:
                events.append({
                    "id": f"scan-start-{s.id}",
                    "kind": "scan_start",
                    "title": f"Scan started: {s.scan_type}",
                    "target": host,
                    "severity": None,
                    "status": s.status,
                    "ts": s.started_at.isoformat(),
                })
            if s.completed_at:
                events.append({
                    "id": f"scan-end-{s.id}",
                    "kind": "scan_end",
                    "title": f"Scan completed: {s.scan_type}",
                    "target": host,
                    "severity": None,
                    "status": s.status,
                    "ts": s.completed_at.isoformat(),
                })

        # Finding events (use scan's completed_at as proxy when finding has no own timestamp)
        scan_ids = [s.id for s in scans]
        findings = db.query(Finding).filter(Finding.scan_id.in_(scan_ids)).all() if scan_ids else []
        scan_time_map = {
            s.id: (s.completed_at or s.started_at) for s in scans
        }
        for f in findings:
            ts_raw = scan_time_map.get(f.scan_id)
            if not ts_raw:
                continue
            events.append({
                "id": f"finding-{f.id}",
                "kind": "finding",
                "title": f.title or "Finding",
                "target": target_map.get(
                    next((s.target_id for s in scans if s.id == f.scan_id), None), "unknown"
                ),
                "severity": f.severity,
                "status": None,
                "ts": ts_raw.isoformat(),
            })

    # Sort by timestamp (oldest first)
    events.sort(key=lambda e: e["ts"])
    return events


# ── FP Suppression Rule endpoints ────────────────────────────────────────────


class FPRuleCreate(BaseModel):
    tool: Optional[str] = None        # None = any tool
    title_contains: str


@router.get("/{project_id}/fp-rules")
def list_fp_rules(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")
    rules = db.query(FPSuppressionRule).filter(FPSuppressionRule.project_id == project_id).all()
    return [
        {"id": r.id, "tool": r.tool, "title_contains": r.title_contains, "created_at": str(r.created_at)}
        for r in rules
    ]


@router.post("/{project_id}/fp-rules", status_code=201)
def create_fp_rule(project_id: str, payload: FPRuleCreate, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")
    tc = payload.title_contains.strip()
    if not tc:
        raise HTTPException(400, "title_contains must not be empty")
    if len(tc) > 500:
        raise HTTPException(400, "title_contains too long (max 500 chars)")
    rule = FPSuppressionRule(
        id=str(uuid.uuid4()),
        project_id=project_id,
        tool=payload.tool.strip() if payload.tool else None,
        title_contains=tc,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return {"id": rule.id, "tool": rule.tool, "title_contains": rule.title_contains, "created_at": str(rule.created_at)}


@router.delete("/{project_id}/fp-rules/{rule_id}", status_code=204)
def delete_fp_rule(project_id: str, rule_id: str, db: Session = Depends(get_db)):
    rule = db.query(FPSuppressionRule).filter(
        FPSuppressionRule.id == rule_id,
        FPSuppressionRule.project_id == project_id,
    ).first()
    if not rule:
        raise HTTPException(404, "Rule not found")
    db.delete(rule)
    db.commit()


# ── Standalone target endpoints ───────────────────────────────────────────────

targets_router = APIRouter(prefix="/targets", tags=["targets"])


@targets_router.get("")
def list_all_targets(project_id: Optional[str] = None, db: Session = Depends(get_db)):
    q = db.query(Target)
    if project_id:
        q = q.filter(Target.project_id == project_id)
    return q.order_by(Target.created_at.desc()).all()


@targets_router.get("/{target_id}", response_model=TargetResponse)
def get_target(target_id: str, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@targets_router.put("/{target_id}", response_model=TargetSummary)
def update_target(
    target_id: str, payload: TargetUpdate, db: Session = Depends(get_db)
):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    if payload.hostname_or_ip is not None:
        target.hostname_or_ip = payload.hostname_or_ip
    if payload.target_type is not None:
        target.target_type = payload.target_type
    if payload.ports is not None:
        target.ports = payload.ports
    if payload.notes is not None:
        target.notes = payload.notes
    db.commit()
    db.refresh(target)
    return target


@targets_router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(target_id: str, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    db.delete(target)
    db.commit()
