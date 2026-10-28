"""Small lookup-or-404 helpers for the most-repeated
`db.query(Model).filter(Model.id == id).first(); if not row: raise
HTTPException(404, ...)` pattern. Plain functions (not FastAPI
dependencies) so they're usable from both route handlers and services,
including call sites where the id isn't a path param.

`services.deps.require_project` is the FastAPI-dependency form of
`get_project_or_404` for the common case where `project_id` *is* a path
param — prefer it in new routes.
"""
from fastapi import HTTPException
from sqlalchemy.orm import Session

from database import Project, Target, Scan


def get_project_or_404(db: Session, project_id: str) -> Project:
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def get_target_or_404(db: Session, target_id: str) -> Target:
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


def get_scan_or_404(db: Session, scan_id: str) -> Scan:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
