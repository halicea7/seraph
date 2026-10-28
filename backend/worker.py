"""Seraph background worker — runs the scheduler, listener manager, and the
durable job queue outside the API process.

Previously these all started inside main.py's FastAPI lifespan, in the same
process serving HTTP/WebSocket traffic. That meant restarting the API
process (a deploy, a crash, a container restart) interrupted every
scheduled scan, every listener, and every in-flight auto-probe. None of
that actually depends on the API process — scheduled/background work was
only ever living there because that's where it happened to be started.

register_profile/register_listener (called from routers/profiles.py and
routers/listeners.py, which still run in the API process) mutate a
`scheduler` object that only exists in *that* process's memory — a no-op
as far as this process's actual running scheduler is concerned. That's why
sync_profiles/sync_listeners (services/scheduler.py,
services/listener_manager.py) periodically re-reconcile against the DB
instead: the API process's job is just to persist the user's intent there.

Run with: python worker.py  (same image as the API container; see
docker-compose.yml's `worker` service, which waits for the backend
container's healthcheck so this process never races it over schema
migrations — this process does not run them itself.)
"""
import asyncio
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("seraph.worker")


async def main() -> None:
    from services.tool_registry import initialize_registry
    from services.background import start_background_jobs

    initialize_registry()
    start_background_jobs()

    log.info("Worker started: scheduler + listener manager + job queue poller running")
    await asyncio.Event().wait()  # run forever


if __name__ == "__main__":
    asyncio.run(main())
