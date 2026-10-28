"""In-process pub/sub for the live event feed served over /ws/events.

Moved out of routers/ws.py so services (scheduler.py, auto_probe.py) can
publish events without importing a router module — a layering violation
that also made those services depend on FastAPI/WebSocket machinery they
have no other reason to import.
"""
import asyncio

_event_clients: set[asyncio.Queue] = set()


async def broadcast_event(event: dict) -> None:
    """Push an event to all connected /ws/events clients."""
    dead = set()
    for q in _event_clients:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            dead.add(q)
    _event_clients.difference_update(dead)
