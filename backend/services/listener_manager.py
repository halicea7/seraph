"""
Audit Listener Manager
Registers/unregisters APScheduler jobs for Listener records.
Three types: scheduled (cron audit runs), threshold (finding count alerts),
healthcheck (TCP port reachability checks).
"""

import asyncio
import json
import logging
from datetime import datetime

from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from services.scheduler import scheduler, _run_headless

log = logging.getLogger(__name__)

_PREFIX = "listener_"


def _job_id(listener_id: str) -> str:
    return f"{_PREFIX}{listener_id}"


def _record_event(db, listener_id: str, outcome: str, detail: str) -> None:
    from database import ListenerEvent

    ev = ListenerEvent(listener_id=listener_id, outcome=outcome, detail=detail)
    db.add(ev)
    db.commit()


# ── Scheduled ─────────────────────────────────────────────────────────────────

async def _fire_scheduled(listener_id: str) -> None:
    from database import SessionLocal, Listener, Scan, Target, Project
    from services.script_generator import generate_script

    db = SessionLocal()
    scan_id = None
    script = None
    try:
        listener = db.query(Listener).filter(Listener.id == listener_id).first()
        if not listener or listener.status != "running":
            return

        config = json.loads(listener.config_json or "{}")
        cats = config.get("scan_categories", [])
        credential_id = config.get("credential_id")

        if not cats:
            _record_event(db, listener_id, "skipped", "No scan categories configured")
            return

        target = (
            db.query(Target).filter(Target.id == listener.target_id).first()
            if listener.target_id
            else None
        )
        project = db.query(Project).filter(Project.id == listener.project_id).first()
        if not target or not project:
            _record_event(db, listener_id, "error", "Target or project not found")
            return

        script = generate_script(
            project_name=project.name,
            target=target.hostname_or_ip,
            scan_categories=cats,
        )

        scan_config: dict = {"categories": cats}
        if credential_id:
            scan_config["credential_id"] = credential_id

        scan = Scan(
            target_id=target.id,
            scan_type=",".join(c["category_id"] for c in cats),
            module="audit",
            status="running",
            started_at=datetime.utcnow(),
            config_json=json.dumps(scan_config),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id

        listener.last_triggered = datetime.utcnow()
        db.commit()
        _record_event(db, listener_id, "triggered", f"Launched scan {scan_id[:8]}")
    finally:
        db.close()

    if scan_id and script:
        await _run_headless(scan_id, script)


# ── Threshold ─────────────────────────────────────────────────────────────────

async def _fire_threshold(listener_id: str) -> None:
    from database import SessionLocal, Listener, Finding, Target, Scan
    from routers.notifications import push_notification

    db = SessionLocal()
    try:
        listener = db.query(Listener).filter(Listener.id == listener_id).first()
        if not listener or listener.status != "running":
            return

        config = json.loads(listener.config_json or "{}")
        severity = config.get("severity", "critical")
        limit = int(config.get("limit", 5))

        target_ids = [
            t.id
            for t in db.query(Target)
            .filter(Target.project_id == listener.project_id)
            .all()
        ]
        scan_ids = (
            [
                s.id
                for s in db.query(Scan).filter(Scan.target_id.in_(target_ids)).all()
            ]
            if target_ids
            else []
        )

        q = db.query(Finding).filter(Finding.severity == severity)
        if scan_ids:
            q = q.filter(Finding.scan_id.in_(scan_ids))
        count = q.count()

        if count >= limit:
            listener.last_triggered = datetime.utcnow()
            db.commit()
            _record_event(
                db, listener_id, "triggered",
                f"{count} {severity} finding(s) — limit {limit}",
            )
            push_notification(
                db,
                title=f"Threshold alert: {listener.name}",
                body=f"{count} {severity} findings detected (limit: {limit}).",
                type="critical" if severity in ("critical", "high") else "warning",
            )
        else:
            _record_event(
                db, listener_id, "skipped",
                f"{count}/{limit} {severity} findings — threshold not met",
            )
    finally:
        db.close()


# ── Health check ──────────────────────────────────────────────────────────────

async def _fire_healthcheck(listener_id: str) -> None:
    from database import SessionLocal, Listener, Target
    from routers.notifications import push_notification

    db = SessionLocal()
    try:
        listener = db.query(Listener).filter(Listener.id == listener_id).first()
        if not listener or listener.status != "running":
            return

        config = json.loads(listener.config_json or "{}")
        port = int(config.get("port", 80))
        timeout = float(config.get("timeout_seconds", 10))
        alert_on = config.get("alert_on", "down")  # down | up | both

        target = (
            db.query(Target).filter(Target.id == listener.target_id).first()
            if listener.target_id
            else None
        )
        if not target:
            _record_event(db, listener_id, "error", "No target configured")
            return

        host = target.hostname_or_ip
        is_up = False
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            is_up = True
        except Exception:
            is_up = False

        status_str = "up" if is_up else "down"
        should_alert = alert_on == "both" or alert_on == status_str

        listener.last_triggered = datetime.utcnow()
        db.commit()

        if should_alert:
            _record_event(db, listener_id, "triggered", f"{host}:{port} is {status_str}")
            push_notification(
                db,
                title=f"Health check: {listener.name}",
                body=f"{host}:{port} is {status_str}.",
                type="critical" if not is_up else "info",
            )
        else:
            _record_event(
                db, listener_id, "skipped",
                f"{host}:{port} is {status_str} — alert_on={alert_on}",
            )
    finally:
        db.close()


# ── Agent Audit ───────────────────────────────────────────────────────────────

async def _fire_agent_audit(listener_id: str) -> None:
    from database import SessionLocal, Listener, Agent, AgentJob, Scan
    from services.script_generator import generate_script

    db = SessionLocal()
    try:
        listener = db.query(Listener).filter(Listener.id == listener_id).first()
        if not listener or listener.status != "running":
            return

        config = json.loads(listener.config_json or "{}")
        agent_id = config.get("agent_id")
        categories = config.get("categories", [])  # list of category id strings

        if not agent_id:
            _record_event(db, listener_id, "error", "No agent_id configured")
            return
        if not categories:
            _record_event(db, listener_id, "skipped", "No audit categories configured")
            return

        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            _record_event(db, listener_id, "error", f"Agent {agent_id[:8]} not found")
            return

        scan_categories = [{"category_id": c} for c in categories]
        script = generate_script(
            project_name="agent",
            target="localhost",
            scan_categories=scan_categories,
        )

        # Create Scan record if agent has a target
        scan_id = None
        if agent.target_id:
            scan = Scan(
                target_id=agent.target_id,
                scan_type=",".join(categories),
                module="audit",
                status="pending",
                created_at=datetime.utcnow(),
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)
            scan_id = scan.id

        job = AgentJob(
            agent_id=agent.id,
            scan_id=scan_id,
            categories=",".join(categories),
            script=script,
            status="pending",
        )
        db.add(job)

        listener.last_triggered = datetime.utcnow()
        db.commit()
        _record_event(
            db, listener_id, "triggered",
            f"Queued agent audit job for agent {agent.name} ({len(categories)} categories)",
        )
    finally:
        db.close()


# ── Registration ──────────────────────────────────────────────────────────────

def register_listener(listener_id: str, listener_type: str, config: dict) -> None:
    job_id = _job_id(listener_id)
    if listener_type == "scheduled":
        cron = config.get("cron", "0 2 * * *")
        trigger = CronTrigger.from_crontab(cron, timezone="UTC")
        scheduler.add_job(
            _fire_scheduled, trigger=trigger, args=[listener_id],
            id=job_id, replace_existing=True,
        )
    elif listener_type == "threshold":
        minutes = max(1, int(config.get("check_interval_minutes", 60)))
        scheduler.add_job(
            _fire_threshold, trigger=IntervalTrigger(minutes=minutes),
            args=[listener_id], id=job_id, replace_existing=True,
        )
    elif listener_type == "healthcheck":
        minutes = max(1, int(config.get("interval_minutes", 5)))
        scheduler.add_job(
            _fire_healthcheck, trigger=IntervalTrigger(minutes=minutes),
            args=[listener_id], id=job_id, replace_existing=True,
        )
    elif listener_type == "agent_audit":
        cron = config.get("cron", "0 2 * * *")
        trigger = CronTrigger.from_crontab(cron, timezone="UTC")
        scheduler.add_job(
            _fire_agent_audit, trigger=trigger, args=[listener_id],
            id=job_id, replace_existing=True,
        )
    else:
        raise ValueError(f"Unknown listener type: {listener_type}")


def unregister_listener(listener_id: str) -> None:
    job_id = _job_id(listener_id)
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)


def initialize_listeners() -> None:
    """Re-register all running listeners on startup."""
    from database import SessionLocal, Listener

    db = SessionLocal()
    try:
        listeners = db.query(Listener).filter(Listener.status == "running").all()
        for listener in listeners:
            config = json.loads(listener.config_json or "{}")
            try:
                register_listener(listener.id, listener.type, config)
            except Exception as e:
                log.error(f"Failed to register listener {listener.id}: {e}")
    finally:
        db.close()
