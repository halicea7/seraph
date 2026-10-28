"""Starts the scheduler, listener manager, and the durable job-queue poller.

Called unconditionally from worker.py. Also called from main.py's lifespan,
unless SERAPH_SCHEDULER_IN_PROCESS=false — set that on the API container
only when a separate worker.py process is deployed alongside it (see
docker-compose.prod.yml's `worker` service) so the same cron jobs don't
fire twice. Everywhere else (./dev.sh, docker-compose.yml,
docker-compose.demo.yml — none of which run a separate worker), the API
process keeps doing this itself, exactly as before this existed.
"""
from apscheduler.triggers.interval import IntervalTrigger


def start_background_jobs() -> None:
    from services.scheduler import initialize_scheduler, scheduler
    from services.listener_manager import initialize_listeners
    from services.job_runner import reset_stale_jobs, poll_pending_jobs

    reset_stale_jobs()
    initialize_scheduler()  # also calls scheduler.start()
    initialize_listeners()
    scheduler.add_job(
        poll_pending_jobs,
        IntervalTrigger(seconds=5),
        id="job_queue_poll",
        replace_existing=True,
    )
