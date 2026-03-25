from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
import json
import uuid
from datetime import datetime

from database import get_db, ScanProfile

router = APIRouter(prefix="/profiles", tags=["profiles"])


class CreateProfileRequest(BaseModel):
    name: str
    description: Optional[str] = ""
    scan_categories: list[dict]  # [{category_id, config}]


@router.get("")
def list_profiles(db: Session = Depends(get_db)):
    return db.query(ScanProfile).order_by(ScanProfile.created_at.desc()).all()


@router.post("")
def create_profile(req: CreateProfileRequest, db: Session = Depends(get_db)):
    if not req.name.strip():
        raise HTTPException(400, "Profile name required")
    profile = ScanProfile(
        id=str(uuid.uuid4()),
        name=req.name.strip(),
        description=req.description or "",
        scan_categories=json.dumps(req.scan_categories),
        created_at=datetime.utcnow(),
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return profile


@router.get("/{profile_id}")
def get_profile(profile_id: str, db: Session = Depends(get_db)):
    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(404, "Profile not found")
    result = {
        "id": profile.id,
        "name": profile.name,
        "description": profile.description,
        "scan_categories": json.loads(profile.scan_categories),
        "created_at": profile.created_at,
    }
    return result


class ScheduleRequest(BaseModel):
    cron: Optional[str] = None          # null to clear the schedule
    project_id: Optional[str] = None
    target_id: Optional[str] = None


@router.put("/{profile_id}/schedule")
def set_schedule(profile_id: str, req: ScheduleRequest, db: Session = Depends(get_db)):
    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(404, "Profile not found")

    from services import scheduler as sched_svc

    if req.cron:
        try:
            sched_svc.register_profile(profile.id, req.cron)
        except Exception as e:
            raise HTTPException(400, str(e))
        profile.schedule = req.cron
        profile.scheduled_project_id = req.project_id
        profile.scheduled_target_id = req.target_id
        profile.next_run = sched_svc._next_fire(req.cron)
    else:
        sched_svc.unregister_profile(profile.id)
        profile.schedule = None
        profile.scheduled_project_id = None
        profile.scheduled_target_id = None
        profile.next_run = None

    db.commit()
    db.refresh(profile)
    return profile


@router.delete("/{profile_id}")
def delete_profile(profile_id: str, db: Session = Depends(get_db)):
    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(404, "Profile not found")
    db.delete(profile)
    db.commit()
    return {"deleted": profile_id}
