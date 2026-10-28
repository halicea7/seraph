"""FastAPI dependency factories: roles, project existence, scope enforcement.

Seraph is single-analyst / trusted-team (no per-project ownership model —
see CLAUDE.md). `require_role` is the one gate on top of `get_current_user`:
destructive routes and raw/ad-hoc command execution require the `admin`
role; everything else stays open to any authenticated `analyst`.

`require_project` and `require_in_scope` replace the
`project = db.query(Project)...; if not project: raise HTTPException(404)`
and `check_scope(...); if not in_scope: raise HTTPException(400)` patterns
repeated ad-hoc across routers, so new routes get 404/400 handling for free
instead of reimplementing it.
"""
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from database import Project, User, get_db
from routers.auth import get_current_user
from services.scope_service import check_scope


def require_role(role: str):
    """FastAPI dependency factory: 403s unless the current user has `role`."""

    def _check(user: User = Depends(get_current_user)) -> User:
        if user.role != role:
            raise HTTPException(status_code=403, detail=f"Requires {role} role")
        return user

    return _check


def require_project(project_id: str, db: Session = Depends(get_db)) -> Project:
    """FastAPI dependency: 404s unless `project_id` (a path param) exists."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def require_in_scope(target_host: str, project: Project) -> None:
    """Raise 400 if `target_host` is out of `project`'s configured scope."""
    in_scope, reason = check_scope(target_host, getattr(project, "scope_json", None))
    if not in_scope:
        raise HTTPException(status_code=400, detail=f"Target out of scope: {reason}")
