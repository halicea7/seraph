from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from database import Credential, User, get_db
from routers.auth import get_current_user
from services.validators import (
    VALID_CRED_SOURCES,
    VALID_CRED_TYPES,
    validate_enum,
    validate_free_text,
    validate_hostname_or_ip,
)

router = APIRouter(prefix="/credentials", tags=["credentials"])


def _masked(c: Credential) -> dict:
    """Credential DTO with the decrypted secret omitted. The vault still
    needs the plaintext for reveal/copy/export — that goes through the
    explicit, audited /reveal and /reveal-batch endpoints below instead of
    riding along on every list fetch."""
    return {
        "id": c.id,
        "project_id": c.project_id,
        "username": c.username,
        "cred_type": c.cred_type,
        "source": c.source,
        "target_host": c.target_host,
        "notes": c.notes,
        "has_secret": bool(c.secret),
        "created_at": c.created_at.isoformat() if c.created_at else None,
    }


class CredentialCreate(BaseModel):
    project_id: str
    username: str = ""
    secret: str = ""
    cred_type: str = "password"   # password, hash, key, token, other
    source: str = "manual"        # manual, c2_loot, osint, brute_force
    target_host: str = ""
    notes: str = ""

    @field_validator("cred_type")
    @classmethod
    def _check_cred_type(cls, v: str) -> str:
        return validate_enum(v, VALID_CRED_TYPES, "cred_type")

    @field_validator("source")
    @classmethod
    def _check_source(cls, v: str) -> str:
        return validate_enum(v, VALID_CRED_SOURCES, "source")

    @field_validator("target_host")
    @classmethod
    def _check_target_host(cls, v: str) -> str:
        return validate_hostname_or_ip(v, allow_empty=True)

    @field_validator("username", "notes")
    @classmethod
    def _check_free_text(cls, v: str) -> str:
        return validate_free_text(v, max_length=1024)


@router.get("")
def list_credentials(
    project_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    creds = (
        db.query(Credential)
        .filter(Credential.project_id == project_id)
        .order_by(Credential.created_at.desc())
        .all()
    )
    return [_masked(c) for c in creds]


@router.post("", status_code=201)
def create_credential(
    req: CredentialCreate,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    cred = Credential(**req.model_dump())
    db.add(cred)
    db.commit()
    db.refresh(cred)
    return _masked(cred)


class RevealBatchRequest(BaseModel):
    ids: list[str]


@router.post("/{cred_id}/reveal")
def reveal_credential(
    cred_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Decrypt and return one credential's secret. POST (not GET) so the
    existing audit_log middleware in main.py records every reveal with the
    requesting user and IP — this is the one place the plaintext leaves the
    vault, and it should always leave a trail."""
    cred = db.query(Credential).filter(Credential.id == cred_id).first()
    if not cred:
        raise HTTPException(404, "Credential not found")
    return {"id": cred.id, "secret": cred.secret}


@router.post("/reveal-batch")
def reveal_credentials_batch(
    req: RevealBatchRequest,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Same as /reveal but for the vault's bulk export/copy actions."""
    creds = db.query(Credential).filter(Credential.id.in_(req.ids)).all()
    return [{"id": c.id, "secret": c.secret} for c in creds]


@router.get("/keys")
def list_key_credentials(
    project_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Return SSH key credentials for a project — secret field omitted."""
    creds = (
        db.query(Credential)
        .filter(Credential.project_id == project_id, Credential.cred_type == "key")
        .order_by(Credential.created_at.desc())
        .all()
    )
    return [
        {
            "id": c.id,
            "username": c.username,
            "target_host": c.target_host,
            "notes": c.notes,
            "created_at": c.created_at.isoformat() if c.created_at else None,
        }
        for c in creds
    ]


@router.delete("/{cred_id}", status_code=204)
def delete_credential(
    cred_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    cred = db.query(Credential).filter(Credential.id == cred_id).first()
    if not cred:
        raise HTTPException(404, "Credential not found")
    db.delete(cred)
    db.commit()
