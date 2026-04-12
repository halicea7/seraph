from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import Finding, FindingNote, get_db

router = APIRouter(tags=["evidence"])


class NoteCreate(BaseModel):
    content: str


@router.get("/findings/{finding_id}/notes")
def list_notes(finding_id: str, db: Session = Depends(get_db)):
    if not db.query(Finding).filter(Finding.id == finding_id).first():
        raise HTTPException(404, "Finding not found")
    return (
        db.query(FindingNote)
        .filter(FindingNote.finding_id == finding_id)
        .order_by(FindingNote.created_at)
        .all()
    )


@router.post("/findings/{finding_id}/notes", status_code=201)
def add_note(finding_id: str, req: NoteCreate, db: Session = Depends(get_db)):
    if not db.query(Finding).filter(Finding.id == finding_id).first():
        raise HTTPException(404, "Finding not found")
    note = FindingNote(finding_id=finding_id, content=req.content)
    db.add(note)
    db.commit()
    db.refresh(note)
    return note


@router.delete("/findings/notes/{note_id}", status_code=204)
def delete_note(note_id: str, db: Session = Depends(get_db)):
    note = db.query(FindingNote).filter(FindingNote.id == note_id).first()
    if not note:
        raise HTTPException(404, "Note not found")
    db.delete(note)
    db.commit()


@router.delete("/findings/{finding_id}", status_code=204)
def delete_finding(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    db.query(FindingNote).filter(FindingNote.finding_id == finding_id).delete()
    db.delete(finding)
    db.commit()
