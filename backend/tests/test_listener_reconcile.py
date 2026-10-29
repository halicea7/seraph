"""
Regression test for A3 (SERAPH revalidation review, 2026-10-29): a Listener
flipped to status="running" by a request this process never directly
registered (simulating a different uvicorn worker handling the API call)
must still get picked up by reconcile_listeners() -- that's the whole point
of the 30s periodic reconcile job in docker-compose.prod.yml's 4-worker
deployment.
"""

import asyncio
import json
import uuid

import database
import main  # noqa: F401 -- ensures routers (and their service imports) are loaded


def test_reconcile_picks_up_a_listener_registered_elsewhere():
    database.create_tables()

    from services.scheduler import scheduler, initialize_scheduler
    if not scheduler.running:
        initialize_scheduler()

    import services.listener_manager as lm

    db = database.SessionLocal()
    try:
        project = database.Project(id=str(uuid.uuid4()), name="reconcile-test")
        db.add(project)
        target = database.Target(
            id=str(uuid.uuid4()), project_id=project.id,
            hostname_or_ip="127.0.0.1", target_type="network",
        )
        db.add(target)
        db.commit()

        # Simulate a PATCH /listeners/{id}/start handled by a worker whose
        # own in-process register_listener() call is a no-op (its
        # AsyncIOScheduler was never started) -- only the DB write happens.
        listener = database.Listener(
            id=str(uuid.uuid4()), name="reconcile-test-listener", type="healthcheck",
            project_id=project.id, target_id=target.id, status="running",
            config_json=json.dumps({"port": 80, "interval_minutes": 1, "timeout_seconds": 2, "alert_on": "both"}),
        )
        db.add(listener)
        db.commit()
        listener_id = listener.id
    finally:
        db.close()

    job_id = lm._job_id(listener_id)
    assert scheduler.get_job(job_id) is None, "job should not exist before reconcile runs"

    asyncio.run(lm.reconcile_listeners())

    job = scheduler.get_job(job_id)
    assert job is not None, "reconcile_listeners() did not register a listener it never directly registered"
    assert job.next_run_time is not None
