import asyncio
import json
import os
import stat
import tempfile
from datetime import datetime, timezone
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

scheduler = AsyncIOScheduler(timezone="UTC")


def _next_fire(cron_expr: str) -> Optional[datetime]:
    try:
        trigger = CronTrigger.from_crontab(cron_expr, timezone="UTC")
        return trigger.get_next_fire_time(None, datetime.now(tz=timezone.utc))
    except Exception:
        return None


async def _run_headless(scan_id: str, script: str) -> None:
    """Write script to temp file, execute, save output, auto-parse findings."""
    from database import SessionLocal, Scan, Finding
    from services.output_parser import auto_parse_scan_output

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False, prefix="seraph_sched_") as f:
        f.write(script)
        tmpfile = f.name
    os.chmod(tmpfile, stat.S_IRWXU)

    try:
        proc = await asyncio.create_subprocess_shell(
            f"bash {tmpfile}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
            raw_output = stdout.decode(errors="replace")
            exit_code = proc.returncode
        except asyncio.TimeoutError:
            proc.kill()
            raw_output = "Scheduled scan timed out after 10 minutes."
            exit_code = 1
    finally:
        os.unlink(tmpfile)

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "completed" if exit_code == 0 else "failed"
            scan.completed_at = datetime.utcnow()
            scan.raw_output = raw_output
            db.commit()
            new_findings = 0
            if exit_code == 0:
                before = db.query(Finding).filter(Finding.scan_id == scan_id).count()
                auto_parse_scan_output(scan, db)
                after = db.query(Finding).filter(Finding.scan_id == scan_id).count()
                new_findings = max(0, after - before)
            # Push notification
            from routers.notifications import push_notification
            if exit_code == 0:
                push_notification(
                    db,
                    title=f"Scheduled scan completed",
                    body=f"{new_findings} new finding(s) discovered." if new_findings else "No new findings.",
                    type="info" if new_findings == 0 else "warning",
                )
            else:
                push_notification(
                    db,
                    title="Scheduled scan failed",
                    body=raw_output[:200] if raw_output else "Unknown error.",
                    type="critical",
                )
    finally:
        db.close()


async def run_scheduled_profile(profile_id: str) -> None:
    from database import SessionLocal, Scan, ScanProfile, Target, Project
    from services.script_generator import generate_script

    db = SessionLocal()
    scan_id: Optional[str] = None
    script: Optional[str] = None

    try:
        profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
        if not profile or not getattr(profile, "scheduled_target_id", None):
            return

        target = db.query(Target).filter(Target.id == profile.scheduled_target_id).first()
        project = db.query(Project).filter(Project.id == profile.scheduled_project_id).first()
        if not target or not project:
            return

        cats = (
            json.loads(profile.scan_categories)
            if isinstance(profile.scan_categories, str)
            else profile.scan_categories
        )

        script = generate_script(
            project_name=project.name,
            target=target.hostname_or_ip,
            scan_categories=cats,
        )

        scan = Scan(
            target_id=profile.scheduled_target_id,
            scan_type=",".join(c["category_id"] for c in cats),
            module="audit",
            status="running",
            started_at=datetime.utcnow(),
            config_json=json.dumps({"categories": cats}),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id

        profile.last_run = datetime.utcnow()
        profile.next_run = _next_fire(profile.schedule)
        db.commit()
    finally:
        db.close()

    if scan_id and script:
        await _run_headless(scan_id, script)


def register_profile(profile_id: str, cron_expr: str) -> None:
    trigger = CronTrigger.from_crontab(cron_expr, timezone="UTC")
    scheduler.add_job(
        run_scheduled_profile,
        trigger=trigger,
        args=[profile_id],
        id=f"profile_{profile_id}",
        replace_existing=True,
    )


def unregister_profile(profile_id: str) -> None:
    job_id = f"profile_{profile_id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)


def initialize_scheduler() -> None:
    from database import SessionLocal, ScanProfile

    db = SessionLocal()
    try:
        profiles = db.query(ScanProfile).all()
        for p in profiles:
            sched = getattr(p, "schedule", None)
            if sched:
                try:
                    register_profile(p.id, sched)
                except Exception:
                    pass
    finally:
        db.close()

    scheduler.start()
