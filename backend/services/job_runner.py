"""Consuming side of the durable job queue (database.Job) -- runs only in
worker.py, registered there as a periodic APScheduler job. The API process
only enqueues (services/job_queue.py); it never executes a Job row itself,
which is what lets this work survive an API-process restart.
"""
import json
import logging
from datetime import datetime

from database import Job, SessionLocal

log = logging.getLogger(__name__)


async def _run_auto_probe_job(payload: dict) -> None:
    from services.auto_probe import run_auto_probe
    await run_auto_probe(
        payload["target_id"], payload["target_host"], payload["tools"], payload["intensity"],
    )


_HANDLERS = {
    "auto_probe": _run_auto_probe_job,
}


async def poll_pending_jobs() -> None:
    """APScheduler job: pick up pending Job rows and run each one as its
    own task, so one slow job doesn't delay the next poll tick or other
    concurrently-picked-up jobs."""
    import asyncio

    db = SessionLocal()
    try:
        pending = db.query(Job).filter(Job.status == "pending").order_by(Job.created_at).limit(10).all()
        picked = [(j.id, j.job_type, j.payload_json) for j in pending]
        for job in pending:
            job.status = "running"
            job.started_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()

    for job_id, job_type, payload_json in picked:
        asyncio.create_task(_execute_job(job_id, job_type, payload_json))


async def _execute_job(job_id: str, job_type: str, payload_json: str) -> None:
    handler = _HANDLERS.get(job_type)
    if not handler:
        _mark_failed(job_id, f"No handler registered for job_type={job_type!r}")
        return
    try:
        await handler(json.loads(payload_json))
        _mark_completed(job_id)
    except Exception as exc:
        log.exception("Job %s (%s) failed", job_id, job_type)
        _mark_failed(job_id, str(exc))


def _mark_completed(job_id: str) -> None:
    db = SessionLocal()
    try:
        job = db.query(Job).filter(Job.id == job_id).first()
        if job:
            job.status = "completed"
            job.completed_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


def _mark_failed(job_id: str, error: str) -> None:
    db = SessionLocal()
    try:
        job = db.query(Job).filter(Job.id == job_id).first()
        if job:
            job.status = "failed"
            job.error = error[:2000]
            job.completed_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


def reset_stale_jobs() -> None:
    """On worker startup, recover jobs left 'running' by a previous crash
    of the worker process itself -- mirrors main.py's _reset_stale_scans."""
    db = SessionLocal()
    try:
        stale = db.query(Job).filter(Job.status == "running").all()
        for job in stale:
            job.status = "pending"
            job.started_at = None
        if stale:
            db.commit()
            log.info("Reset %d stale job(s) to pending on worker startup", len(stale))
    finally:
        db.close()
