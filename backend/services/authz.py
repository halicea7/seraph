"""Role-based access helpers.

Seraph is single-analyst / trusted-team (no per-project ownership model —
see CLAUDE.md). `require_role` is the one gate we add on top of
`get_current_user`: destructive routes and raw/ad-hoc command execution
require the `admin` role; everything else stays open to any authenticated
`analyst`.
"""
from fastapi import Depends, HTTPException

from database import User
from routers.auth import get_current_user


def require_role(role: str):
    """FastAPI dependency factory: 403s unless the current user has `role`."""

    def _check(user: User = Depends(get_current_user)) -> User:
        if user.role != role:
            raise HTTPException(status_code=403, detail=f"Requires {role} role")
        return user

    return _check
