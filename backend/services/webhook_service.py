"""
Webhook delivery service.

Fires outbound HTTP POSTs whenever a notification is pushed. Signs the payload
with HMAC-SHA256 when a secret is configured, and retries on failure with
exponential backoff (3 attempts: immediate, +30 s, +5 m).

Delivery attempts are logged to the WebhookDelivery table regardless of outcome.
Failures are never surfaced to callers — a broken webhook must not disrupt normal
operation.
"""

import asyncio
import hashlib
import hmac
import json
import time
import urllib.request
import urllib.error
from typing import Optional


_COLORS = {"critical": 0xEF4444, "warning": 0xF59E0B, "info": 0x06B6D4}
_EMOJIS = {"critical": "🚨", "warning": "⚠️", "info": "ℹ️"}

# Retry delays in seconds: attempt 1 is immediate (0 s), attempt 2 after 30 s,
# attempt 3 after a further 5 m (300 s).
_RETRY_DELAYS = [0, 30, 300]


def _build_payload(url: str, title: str, body: str, event_type: str) -> dict:
    emoji = _EMOJIS.get(event_type, "📌")
    color_hex = _COLORS.get(event_type, 0x64748B)
    if "discord.com/api/webhooks" in url:
        return {
            "embeds": [{
                "title": f"{emoji} {title}",
                "description": body or "\u200b",
                "color": color_hex,
            }]
        }
    # Slack / Teams / generic
    return {
        "text": f"{emoji} *{title}*" + (f"\n{body}" if body else ""),
        "attachments": [{"color": f"#{color_hex:06x}", "text": body}] if body else [],
    }


def _sign(secret: str, body: bytes) -> str:
    """Return HMAC-SHA256 hex digest of body signed with secret."""
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _post_sync(url: str, payload: dict, secret: Optional[str]) -> tuple[int, str]:
    """POST payload to url. Returns (status_code, error_message)."""
    data = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if secret:
        headers["X-Seraph-Signature"] = f"sha256={_sign(secret, data)}"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return resp.status, ""
    except urllib.error.HTTPError as e:
        return e.code, str(e)
    except Exception as e:
        return 0, str(e)


def _log_delivery(
    webhook_id: str,
    event_type: str,
    title: str,
    status_code: int,
    attempt: int,
    success: bool,
    error: str,
) -> None:
    """Write a WebhookDelivery row. Failures are swallowed."""
    try:
        from database import SessionLocal, WebhookDelivery
        db = SessionLocal()
        try:
            row = WebhookDelivery(
                webhook_id=webhook_id,
                event_type=event_type,
                title=title,
                status_code=status_code or None,
                attempt=attempt,
                success=success,
                error=error or None,
            )
            db.add(row)
            db.commit()
        finally:
            db.close()
    except Exception:
        pass


async def fire_webhooks(
    event_type: str,
    title: str,
    body: str = "",
    scan_id: Optional[str] = None,
) -> None:
    """Query active webhooks matching event_type and POST to each with retry."""
    from database import SessionLocal, WebhookConfig

    db = SessionLocal()
    try:
        hooks = db.query(WebhookConfig).filter(WebhookConfig.active == True).all()
        # Detach from session so we can use values after db.close()
        hooks_data = [
            {"id": h.id, "url": h.url, "events": h.events, "secret": h.secret}
            for h in hooks
        ]
    finally:
        db.close()

    for hook in hooks_data:
        allowed = {e.strip() for e in hook["events"].split(",") if e.strip()}
        if event_type not in allowed and "all" not in allowed:
            continue

        payload = _build_payload(hook["url"], title, body, event_type)

        success = False
        for attempt_num, delay in enumerate(_RETRY_DELAYS, start=1):
            if delay > 0:
                await asyncio.sleep(delay)
            status_code, error = await asyncio.to_thread(
                _post_sync, hook["url"], payload, hook["secret"]
            )
            ok = 200 <= status_code < 300
            _log_delivery(
                webhook_id=hook["id"],
                event_type=event_type,
                title=title,
                status_code=status_code,
                attempt=attempt_num,
                success=ok,
                error=error,
            )
            if ok:
                success = True
                break
            # Only retry on network / 5xx errors; 4xx means the receiver rejected it
            if 400 <= status_code < 500:
                break
        # Webhook failures are always silent at the caller level
