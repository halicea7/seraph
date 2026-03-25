from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
import json
import uuid
from datetime import datetime

from database import get_db, Listener, ListenerEvent, Target, Project

router = APIRouter(prefix="/listeners", tags=["listeners"])


class ListenerCreate(BaseModel):
    name: str
    type: str           # scheduled | threshold | healthcheck
    project_id: str
    target_id: Optional[str] = None
    config: dict = {}


def _serialize(listener: Listener) -> dict:
    return {
        "id": listener.id,
        "name": listener.name,
        "type": listener.type,
        "project_id": listener.project_id,
        "target_id": listener.target_id,
        "config": json.loads(listener.config_json or "{}"),
        "status": listener.status,
        "last_triggered": listener.last_triggered.isoformat() if listener.last_triggered else None,
        "created_at": listener.created_at.isoformat() if listener.created_at else None,
    }


def _serialize_event(event: ListenerEvent) -> dict:
    return {
        "id": event.id,
        "listener_id": event.listener_id,
        "fired_at": event.fired_at.isoformat() if event.fired_at else None,
        "outcome": event.outcome,
        "detail": event.detail,
    }


@router.get("")
def list_listeners(project_id: Optional[str] = None, db: Session = Depends(get_db)):
    q = db.query(Listener)
    if project_id:
        q = q.filter(Listener.project_id == project_id)
    return [_serialize(l) for l in q.order_by(Listener.created_at.desc()).all()]


@router.post("", status_code=201)
def create_listener(req: ListenerCreate, db: Session = Depends(get_db)):
    if not db.query(Project).filter(Project.id == req.project_id).first():
        raise HTTPException(404, "Project not found")
    if req.target_id and not db.query(Target).filter(Target.id == req.target_id).first():
        raise HTTPException(404, "Target not found")

    listener = Listener(
        id=str(uuid.uuid4()),
        name=req.name,
        type=req.type,
        project_id=req.project_id,
        target_id=req.target_id or None,
        config_json=json.dumps(req.config),
        status="stopped",
    )
    db.add(listener)
    db.commit()
    db.refresh(listener)
    return _serialize(listener)


@router.get("/events/all")
def get_all_events(db: Session = Depends(get_db)):
    events = (
        db.query(ListenerEvent)
        .order_by(ListenerEvent.fired_at.desc())
        .limit(200)
        .all()
    )
    return [_serialize_event(e) for e in events]


@router.get("/{listener_id}")
def get_listener(listener_id: str, db: Session = Depends(get_db)):
    listener = db.query(Listener).filter(Listener.id == listener_id).first()
    if not listener:
        raise HTTPException(404, "Listener not found")
    return _serialize(listener)


@router.patch("/{listener_id}/start")
def start_listener(listener_id: str, db: Session = Depends(get_db)):
    listener = db.query(Listener).filter(Listener.id == listener_id).first()
    if not listener:
        raise HTTPException(404, "Listener not found")

    from services.listener_manager import register_listener
    try:
        config = json.loads(listener.config_json or "{}")
        register_listener(listener.id, listener.type, config)
    except Exception as e:
        raise HTTPException(400, str(e))

    listener.status = "running"
    db.commit()
    return _serialize(listener)


@router.patch("/{listener_id}/stop")
def stop_listener(listener_id: str, db: Session = Depends(get_db)):
    listener = db.query(Listener).filter(Listener.id == listener_id).first()
    if not listener:
        raise HTTPException(404, "Listener not found")

    from services.listener_manager import unregister_listener
    unregister_listener(listener.id)
    listener.status = "stopped"
    db.commit()
    return _serialize(listener)


@router.patch("/{listener_id}/pause")
def pause_listener(listener_id: str, db: Session = Depends(get_db)):
    listener = db.query(Listener).filter(Listener.id == listener_id).first()
    if not listener:
        raise HTTPException(404, "Listener not found")

    from services.listener_manager import unregister_listener
    unregister_listener(listener.id)
    listener.status = "paused"
    db.commit()
    return _serialize(listener)


@router.delete("/{listener_id}", status_code=204)
def delete_listener(listener_id: str, db: Session = Depends(get_db)):
    listener = db.query(Listener).filter(Listener.id == listener_id).first()
    if not listener:
        raise HTTPException(404, "Listener not found")

    from services.listener_manager import unregister_listener
    unregister_listener(listener.id)
    db.delete(listener)
    db.commit()


@router.get("/{listener_id}/events")
def get_listener_events(listener_id: str, db: Session = Depends(get_db)):
    events = (
        db.query(ListenerEvent)
        .filter(ListenerEvent.listener_id == listener_id)
        .order_by(ListenerEvent.fired_at.desc())
        .limit(100)
        .all()
    )
    return [_serialize_event(e) for e in events]
