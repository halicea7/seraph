import asyncio
import re
import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from database import Credential, Finding, Project, Scan, Target, VulnerabilityRecord, get_db

router = APIRouter(prefix="/projects", tags=["projects"])

# Validation pattern: allow valid IPs, hostnames, and domain names
HOSTNAME_IP_PATTERN = re.compile(
    r"^(?:"
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"  # IPv4
    r"|"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"  # hostname/domain
    r")$"
)

VALID_TARGET_TYPES = {"linux_host", "windows_host", "web_app", "cloud_aws", "network"}


# ── Pydantic schemas ──────────────────────────────────────────────────────────


class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


class ProjectResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    created_at: datetime
    target_count: int = 0

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
    projects = db.query(Project).order_by(Project.created_at.desc()).all()
    result = []
    for p in projects:
        result.append(
            ProjectResponse(
                id=p.id,
                name=p.name,
                description=p.description,
                created_at=p.created_at,
                target_count=len(p.targets),
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
    # VulnerabilityRecord and Credential have project_id FKs without cascade
    db.query(VulnerabilityRecord).filter(VulnerabilityRecord.project_id == project_id).delete()
    db.query(Credential).filter(Credential.project_id == project_id).delete()
    db.delete(project)
    db.commit()


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
            "cve_id": f.cve_id,
            "cvss_score": f.cvss_score,
            "status": getattr(f, "status", "open") or "open",
            "tags": getattr(f, "tags", "") or "",
            "target": target.hostname_or_ip if target else "unknown",
            "project": project.name if project else "unknown",
            "project_id": project.id if project else None,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        })
    return result


@stats_router.patch("/findings/{finding_id}/status")
def update_finding_status(finding_id: str, payload: dict, db: Session = Depends(get_db)):
    valid = {"open", "in-review", "remediated", "accepted"}
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
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        })
    return result


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
