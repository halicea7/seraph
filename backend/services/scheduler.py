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

    # Daily CVE watchlist check — runs at 03:00 UTC
    scheduler.add_job(
        _run_cve_check,
        CronTrigger.from_crontab("0 3 * * *", timezone="UTC"),
        id="cve_daily_check",
        replace_existing=True,
    )

    # C2 session auto-sync — every 30 seconds
    from apscheduler.triggers.interval import IntervalTrigger
    scheduler.add_job(
        _run_c2_session_sync,
        IntervalTrigger(seconds=30),
        id="c2_session_sync",
        replace_existing=True,
    )

    # Nessus scan-job poller — follows live scans/exports to completion every 20s
    scheduler.add_job(
        _run_nessus_poll,
        IntervalTrigger(seconds=20),
        id="nessus_poll",
        replace_existing=True,
    )

    scheduler.start()


async def _run_cve_check() -> None:
    """APScheduler job: check all watched services for new CVEs."""
    from services.cve_watcher import check_all_watched_services
    try:
        await check_all_watched_services()
    except Exception:
        pass


async def _run_c2_session_sync() -> None:
    """
    APScheduler job: pull live sessions from MSF and Sliver, upsert Seraph
    C2Session records for all projects that have active sessions.

    Runs every 30 s.  Only active sessions are synced; dead/inactive sessions
    already in the DB are transitioned to 'lost' if they no longer appear in
    the live list.
    """
    from database import SessionLocal, C2Session, Target, AppSetting
    import services.msf_client as msf
    import services.sliver_client as sliver
    import uuid as _uuid
    import json as _json
    from routers.c2 import _DEFAULT_CHECKLIST

    db = SessionLocal()
    try:
        # ── MSF sync ─────────────────────────────────────────────────
        try:
            live_msf = msf.list_sessions()  # returns [] if not connected
        except Exception:
            live_msf = []

        live_msf_ids = {str(s["msf_session_id"]) for s in live_msf}

        # Collect all project IDs that already have C2 sessions
        project_ids = [
            row[0] for row in db.query(C2Session.project_id).distinct().all()
        ]
        if not project_ids and live_msf:
            # Fallback: use first project found
            from database import Project
            p = db.query(Project).first()
            if p:
                project_ids = [p.id]

        for project_id in project_ids:
            # Mark sessions that disappeared as 'lost'
            db.query(C2Session).filter(
                C2Session.project_id == project_id,
                C2Session.status == "active",
                C2Session.msf_session_id.notin_(live_msf_ids),
                C2Session.session_type.notlike("sliver_%"),  # don't touch sliver sessions here
            ).update({"status": "lost"}, synchronize_session=False)

        for ls in live_msf:
            sid = str(ls["msf_session_id"])
            existing = db.query(C2Session).filter(C2Session.msf_session_id == sid).first()
            if existing:
                # Refresh last_seen and status
                existing.status = "active"
                existing.last_seen = datetime.utcnow()
            else:
                # Create in first project if we have one
                project_id = project_ids[0] if project_ids else None
                if not project_id:
                    continue
                remote_host = ls.get("remote_host", "")
                target = None
                if remote_host:
                    target = db.query(Target).filter(
                        Target.project_id == project_id,
                        Target.hostname_or_ip == remote_host,
                    ).first()
                session = C2Session(
                    id=str(_uuid.uuid4()),
                    project_id=project_id,
                    target_id=target.id if target else None,
                    msf_session_id=sid,
                    session_type=ls.get("session_type", "shell"),
                    platform=ls.get("platform", ""),
                    arch=ls.get("arch", ""),
                    remote_host=remote_host,
                    remote_port=ls.get("remote_port", ""),
                    tunnel_peer=ls.get("tunnel_peer", ""),
                    via_exploit=ls.get("via_exploit", ""),
                    via_payload=ls.get("via_payload", ""),
                    status="active",
                    established_at=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    checklist_json=_json.dumps(_DEFAULT_CHECKLIST),
                )
                db.add(session)

        # ── Sliver sync ───────────────────────────────────────────────
        try:
            live_sliver = sliver.list_sessions() if sliver.is_available() else []
        except Exception:
            live_sliver = []

        live_sliver_ids = {str(s["sliver_id"]) for s in live_sliver}

        for project_id in project_ids:
            db.query(C2Session).filter(
                C2Session.project_id == project_id,
                C2Session.status == "active",
                C2Session.session_type.like("sliver_%"),
                C2Session.msf_session_id.notin_(live_sliver_ids),
            ).update({"status": "lost"}, synchronize_session=False)

        for ls in live_sliver:
            sid = str(ls["sliver_id"])
            existing = db.query(C2Session).filter(C2Session.msf_session_id == sid).first()
            if existing:
                existing.status = "active"
                existing.last_seen = datetime.utcnow()
            else:
                project_id = project_ids[0] if project_ids else None
                if not project_id:
                    continue
                remote_host = ls.get("remote_host", "")
                target = None
                if remote_host:
                    target = db.query(Target).filter(
                        Target.project_id == project_id,
                        Target.hostname_or_ip == remote_host,
                    ).first()
                session = C2Session(
                    id=str(_uuid.uuid4()),
                    project_id=project_id,
                    target_id=target.id if target else None,
                    msf_session_id=sid,
                    session_type=ls["session_type"],
                    platform=ls.get("platform", ""),
                    arch=ls.get("arch", ""),
                    remote_host=remote_host,
                    remote_port=ls.get("remote_port", ""),
                    tunnel_peer=ls.get("tunnel_peer", ""),
                    via_exploit="sliver-implant",
                    via_payload=ls.get("via_payload", ""),
                    status="active",
                    established_at=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    checklist_json=_json.dumps(_DEFAULT_CHECKLIST),
                )
                db.add(session)

        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


# Terminal Nessus statuses — stop polling once a job reaches one of these.
_NESSUS_TERMINAL = {"completed", "canceled", "cancelled", "aborted", "empty", "imported"}


async def _run_nessus_poll() -> None:
    """APScheduler job (every 20 s): follow live Nessus scan jobs to completion.

    For each Seraph 'nessus_job' Scan still in flight, poll the Nessus side for
    status/progress, push a 'scan_update' over /ws/events, and on completion fan
    out per-host findings via the shared import. Also advances in-flight exports.
    """
    from database import SessionLocal, Scan, Target
    from services.nessus import load_client, import_scan_results
    from routers.ws import broadcast_event

    db = SessionLocal()
    try:
        jobs = db.query(Scan).filter(
            Scan.scan_type == "nessus_job",
            Scan.nessus_scan_id.isnot(None),
        ).all()
        active = [j for j in jobs if (j.nessus_status or "") not in _NESSUS_TERMINAL]
        if not active:
            return

        try:
            client = load_client(db)
            client.authenticate()
        except Exception:
            return  # not configured / unreachable — try again next tick

        for job in active:
            try:
                data = client.get(f"/scans/{job.nessus_scan_id}")
                info = data.get("info", {})
                status = (info.get("status") or "").lower()
                progress = int(info.get("progress", job.nessus_progress or 0) or 0)

                job.nessus_status = status or job.nessus_status
                job.nessus_progress = progress
                db.commit()

                await broadcast_event({
                    "type": "scan_update", "scan_id": job.id,
                    "status": status, "progress": progress,
                })

                if status == "completed":
                    target = db.query(Target).filter(Target.id == job.target_id).first()
                    project_id = target.project_id if target else None
                    imported = 0
                    if project_id:
                        try:
                            res = import_scan_results(db, client, job.nessus_scan_id, project_id)
                            imported = res.get("findings_created", 0)
                        except Exception:
                            db.rollback()
                    job.status = "completed"
                    job.nessus_status = "completed"
                    job.nessus_progress = 100
                    job.completed_at = datetime.utcnow()
                    db.commit()
                    await broadcast_event({
                        "type": "finding_created", "scan_id": job.id,
                        "findings_created": imported,
                    })

                # ── Advance an in-flight export ──────────────────────────
                if job.nessus_export_json:
                    try:
                        export = json.loads(job.nessus_export_json)
                    except Exception:
                        export = None
                    if export and export.get("state") == "pending" and export.get("file_id"):
                        try:
                            est = client.get(
                                f"/scans/{job.nessus_scan_id}/export/{export['file_id']}/status"
                            ).get("status", "")
                        except Exception:
                            est = ""
                        if est == "ready":
                            export["state"] = "ready"
                            job.nessus_export_json = json.dumps(export)
                            db.commit()
                            await broadcast_event({
                                "type": "nessus_export_ready", "scan_id": job.id,
                                "nessus_scan_id": job.nessus_scan_id,
                                "file_id": export["file_id"], "format": export.get("format"),
                            })
            except Exception:
                db.rollback()
                continue
    except Exception:
        db.rollback()
    finally:
        db.close()
