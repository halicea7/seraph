from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import Notification, get_db
from services.notification_service import push_notification

router = APIRouter(prefix="/notifications", tags=["notifications"])


class NotificationCreate(BaseModel):
    title: str
    body: str = ""
    type: str = "info"


@router.post("", status_code=201)
def create_notification(payload: NotificationCreate, db: Session = Depends(get_db)):
    n = push_notification(db, payload.title, payload.body, payload.type)
    return {"id": n.id}


@router.get("")
def list_notifications(unread_only: bool = False, db: Session = Depends(get_db)):
    q = db.query(Notification).order_by(Notification.created_at.desc())
    if unread_only:
        q = q.filter(Notification.read == False)
    items = q.limit(50).all()
    return [
        {
            "id": n.id,
            "title": n.title,
            "body": n.body,
            "type": n.type,
            "read": n.read,
            "created_at": n.created_at.isoformat() if n.created_at else None,
            "scan_id": getattr(n, "scan_id", None),
        }
        for n in items
    ]


@router.patch("/{notification_id}/read")
def mark_read(notification_id: str, db: Session = Depends(get_db)):
    n = db.query(Notification).filter(Notification.id == notification_id).first()
    if n:
        n.read = True
        db.commit()
    return {"ok": True}


@router.patch("/read-all")
def mark_all_read(db: Session = Depends(get_db)):
    db.query(Notification).filter(Notification.read == False).update({"read": True})
    db.commit()
    return {"ok": True}


@router.delete("/read")
def delete_read(db: Session = Depends(get_db)):
    db.query(Notification).filter(Notification.read == True).delete()
    db.commit()
    return {"ok": True}
