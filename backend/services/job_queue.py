"""Enqueue side of the durable job queue (database.Job). Called from the API
process; services/job_runner.py (the worker process) is the consuming side.
"""
import json

from database import Job, SessionLocal


def enqueue(job_type: str, payload: dict) -> str:
    db = SessionLocal()
    try:
        job = Job(job_type=job_type, payload_json=json.dumps(payload), status="pending")
        db.add(job)
        db.commit()
        return job.id
    finally:
        db.close()
