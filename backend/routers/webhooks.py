import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import WebhookConfig, WebhookDelivery, get_db
from routers.auth import get_current_user

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

VALID_EVENTS = {"critical", "warning", "info", "all"}


class WebhookCreate(BaseModel):
    name: str
    url: str
    events: list[str] = ["critical", "warning"]
    active: bool = True
    secret: Optional[str] = None   # HMAC signing secret (optional)


class WebhookUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    events: Optional[list[str]] = None
    active: Optional[bool] = None
    secret: Optional[str] = None


def _serialize(wh: WebhookConfig) -> dict:
    return {
        "id": wh.id,
        "name": wh.name,
        "url": wh.url,
        "events": [e.strip() for e in wh.events.split(",") if e.strip()],
        "active": wh.active,
        "has_secret": bool(wh.secret),   # never expose the secret value itself
        "created_at": str(wh.created_at),
    }


@router.get("")
def list_webhooks(db: Session = Depends(get_db), _=Depends(get_current_user)):
    return [_serialize(wh) for wh in db.query(WebhookConfig).order_by(WebhookConfig.created_at).all()]


@router.post("", status_code=201)
def create_webhook(req: WebhookCreate, db: Session = Depends(get_db), _=Depends(get_current_user)):
    if not req.url.startswith("http"):
        raise HTTPException(400, "URL must start with http:// or https://")
    events = [e for e in req.events if e in VALID_EVENTS]
    if not events:
        raise HTTPException(400, f"events must be one or more of: {VALID_EVENTS}")
    wh = WebhookConfig(
        id=str(uuid.uuid4()),
        name=req.name.strip(),
        url=req.url.strip(),
        events=",".join(events),
        active=req.active,
        secret=req.secret.strip() if req.secret else None,
    )
    db.add(wh)
    db.commit()
    db.refresh(wh)
    return _serialize(wh)


@router.patch("/{wh_id}")
def update_webhook(wh_id: str, req: WebhookUpdate, db: Session = Depends(get_db), _=Depends(get_current_user)):
    wh = db.query(WebhookConfig).filter(WebhookConfig.id == wh_id).first()
    if not wh:
        raise HTTPException(404, "Webhook not found")
    if req.name is not None:
        wh.name = req.name.strip()
    if req.url is not None:
        wh.url = req.url.strip()
    if req.events is not None:
        events = [e for e in req.events if e in VALID_EVENTS]
        wh.events = ",".join(events) if events else wh.events
    if req.active is not None:
        wh.active = req.active
    if req.secret is not None:
        wh.secret = req.secret.strip() or None
    db.commit()
    return _serialize(wh)


@router.delete("/{wh_id}", status_code=204)
def delete_webhook(wh_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    wh = db.query(WebhookConfig).filter(WebhookConfig.id == wh_id).first()
    if not wh:
        raise HTTPException(404, "Webhook not found")
    db.delete(wh)
    db.commit()


@router.post("/{wh_id}/test", status_code=200)
async def test_webhook(wh_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    """Send a test payload to verify the webhook URL works."""
    wh = db.query(WebhookConfig).filter(WebhookConfig.id == wh_id).first()
    if not wh:
        raise HTTPException(404, "Webhook not found")
    from services.webhook_service import fire_webhooks
    await fire_webhooks("info", "Seraph webhook test", "This is a test notification from Seraph.")
    return {"ok": True}


@router.get("/{wh_id}/deliveries")
def list_deliveries(wh_id: str, limit: int = 50, db: Session = Depends(get_db), _=Depends(get_current_user)):
    """Return recent delivery attempts for this webhook."""
    wh = db.query(WebhookConfig).filter(WebhookConfig.id == wh_id).first()
    if not wh:
        raise HTTPException(404, "Webhook not found")
    rows = (
        db.query(WebhookDelivery)
        .filter(WebhookDelivery.webhook_id == wh_id)
        .order_by(WebhookDelivery.fired_at.desc())
        .limit(min(limit, 200))
        .all()
    )
    return [
        {
            "id": r.id,
            "event_type": r.event_type,
            "title": r.title,
            "status_code": r.status_code,
            "attempt": r.attempt,
            "success": r.success,
            "error": r.error,
            "fired_at": str(r.fired_at),
        }
        for r in rows
    ]
