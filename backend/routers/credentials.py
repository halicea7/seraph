from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import Credential, get_db

router = APIRouter(prefix="/credentials", tags=["credentials"])


class CredentialCreate(BaseModel):
    project_id: str
    username: str = ""
    secret: str = ""
    cred_type: str = "password"   # password, hash, key, token, other
    source: str = "manual"        # manual, c2_loot, osint, brute_force
    target_host: str = ""
    notes: str = ""


@router.get("")
def list_credentials(project_id: str, db: Session = Depends(get_db)):
    return (
        db.query(Credential)
        .filter(Credential.project_id == project_id)
        .order_by(Credential.created_at.desc())
        .all()
    )


@router.post("", status_code=201)
def create_credential(req: CredentialCreate, db: Session = Depends(get_db)):
    cred = Credential(**req.model_dump())
    db.add(cred)
    db.commit()
    db.refresh(cred)
    return cred


@router.get("/keys")
def list_key_credentials(project_id: str, db: Session = Depends(get_db)):
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
def delete_credential(cred_id: str, db: Session = Depends(get_db)):
    cred = db.query(Credential).filter(Credential.id == cred_id).first()
    if not cred:
        raise HTTPException(404, "Credential not found")
    db.delete(cred)
    db.commit()
