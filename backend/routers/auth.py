import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db, User
from services.auth_service import hash_password, verify_password, create_token, decode_token

router = APIRouter(prefix="/auth", tags=["auth"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.query(User).filter(User.id == payload.get("sub")).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user


def _user_dict(u: User) -> dict:
    return {"id": u.id, "username": u.username, "role": u.role, "full_name": u.full_name or "", "created_at": str(u.created_at)}


# ── First-run setup ────────────────────────────────────────────────────────────

@router.get("/setup-required")
def setup_required(db: Session = Depends(get_db)):
    """Returns true when no users exist (first run)."""
    return {"required": db.query(User).count() == 0}


class SetupRequest(BaseModel):
    username: str
    password: str
    full_name: Optional[str] = None


@router.post("/setup", status_code=201)
def first_run_setup(req: SetupRequest, db: Session = Depends(get_db)):
    if db.query(User).count() > 0:
        raise HTTPException(400, "Platform already set up. Use /auth/login.")
    if len(req.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")
    user = User(
        id=str(uuid.uuid4()),
        username=req.username.strip(),
        hashed_password=hash_password(req.password),
        role="admin",
        is_active=True,
        full_name=req.full_name.strip() if req.full_name else None,
    )
    db.add(user)
    db.commit()
    token = create_token({"sub": user.id, "role": user.role})
    return {"access_token": token, "token_type": "bearer", "user": _user_dict(user)}


# ── Login ──────────────────────────────────────────────────────────────────────

@router.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    token = create_token({"sub": user.id, "role": user.role})
    return {"access_token": token, "token_type": "bearer", "user": _user_dict(user)}


# ── Current user ───────────────────────────────────────────────────────────────

@router.get("/me")
def get_me(current_user: User = Depends(get_current_user)):
    return _user_dict(current_user)


# ── User management (admin only) ───────────────────────────────────────────────

class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "analyst"
    full_name: Optional[str] = None


@router.post("/users", status_code=201)
def create_user(
    req: CreateUserRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.role != "admin":
        raise HTTPException(403, "Admin role required")
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(400, "Username already taken")
    if len(req.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    role = req.role if req.role in ("admin", "analyst") else "analyst"
    user = User(
        id=str(uuid.uuid4()),
        username=req.username.strip(),
        hashed_password=hash_password(req.password),
        role=role,
        is_active=True,
        full_name=req.full_name.strip() if req.full_name else None,
    )
    db.add(user)
    db.commit()
    return _user_dict(user)


@router.get("/users")
def list_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.role != "admin":
        raise HTTPException(403, "Admin role required")
    return [_user_dict(u) for u in db.query(User).all()]


class UpdateProfileRequest(BaseModel):
    full_name: Optional[str] = None


@router.patch("/me")
def update_me(
    req: UpdateProfileRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if req.full_name is not None:
        current_user.full_name = req.full_name.strip() or None
    db.commit()
    db.refresh(current_user)
    return _user_dict(current_user)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.post("/change-password")
def change_password(
    req: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(req.current_password, current_user.hashed_password):
        raise HTTPException(400, "Current password is incorrect")
    if len(req.new_password) < 8:
        raise HTTPException(400, "New password must be at least 8 characters")
    current_user.hashed_password = hash_password(req.new_password)
    db.commit()
    return {"ok": True}


@router.delete("/users/{user_id}")
def delete_user(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.role != "admin":
        raise HTTPException(403, "Admin role required")
    if user_id == current_user.id:
        raise HTTPException(400, "Cannot delete your own account")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    db.delete(user)
    db.commit()
    return {"deleted": user_id}
