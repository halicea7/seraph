"""Notification creation — moved out of routers/notifications.py so services
(scheduler.py, listener_manager.py) can push notifications without importing
a router module (a layering violation)."""
import asyncio
import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from database import Notification


def push_notification(db: Session, title: str, body: str = "", type: str = "info") -> Notification:
    """Create a notification and fire matching webhooks."""
    n = Notification(
        id=str(uuid.uuid4()),
        title=title,
        body=body,
        type=type,
        created_at=datetime.utcnow(),
    )
    db.add(n)
    db.commit()
    # Fire webhooks if we're inside an async context
    try:
        loop = asyncio.get_running_loop()
        from services.webhook_service import fire_webhooks
        loop.create_task(fire_webhooks(type, title, body))
    except RuntimeError:
        pass  # no running loop — skip (e.g. during tests or sync callers)
    return n
