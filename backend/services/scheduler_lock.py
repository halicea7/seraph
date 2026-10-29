"""
Single-owner lock for the in-process scheduler/listener registry.

docker-compose.prod.yml runs 4 uvicorn workers. main.py's lifespan calls
initialize_scheduler()/initialize_listeners() on startup, and each worker
got its own independent AsyncIOScheduler -- so every cron/interval job
(including every Listener) fired once per worker. A healthcheck listener
set to "every 1 minute" produced 4 events a minute, one per worker.

Fix: a Postgres advisory lock held for the lifetime of the process. Exactly
one worker wins it and becomes the scheduler owner; the other three skip
scheduler/listener startup entirely, so their schedulers never have a single
job registered and fire nothing. The lock is tied to a dedicated connection
held open for the process's life -- it releases automatically if that
connection (or the process) dies, so a crashed owner doesn't wedge the lock.

SQLite (dev / test, always single-process) has no advisory locks and no
multi-worker problem to solve, so it's treated as "always the owner".
"""

import logging

from database import engine

log = logging.getLogger(__name__)

_ADVISORY_LOCK_KEY = 0x5e9a9f  # arbitrary, just needs to be constant across workers
_held_connection = None  # kept open for the process's lifetime; never returned to the pool


def acquire_scheduler_ownership() -> bool:
    """Returns True if this process should run the scheduler/listeners."""
    global _held_connection

    if engine.dialect.name != "postgresql":
        return True

    conn = engine.raw_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT pg_try_advisory_lock(%s)", (_ADVISORY_LOCK_KEY,))
        got_lock = cursor.fetchone()[0]
        cursor.close()
    except Exception:
        log.warning("Could not acquire scheduler advisory lock; assuming ownership", exc_info=True)
        conn.close()
        return True

    if not got_lock:
        conn.close()
        log.info("Another worker already owns the scheduler/listener registry — skipping startup here.")
        return False

    # Detach from the pool so this connection is never recycled/closed out
    # from under the lock by normal pool churn -- it must stay open for as
    # long as this worker process runs.
    conn.detach()
    _held_connection = conn
    log.info("This worker is the scheduler/listener owner.")
    return True
