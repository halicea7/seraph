"""
Web screenshot capture via gowitness.

Builds a gowitness command that screenshots a set of URLs into a per-job output
directory, then indexes the produced images into Screenshot rows. Jobs are held
in database.ScreenshotJob (keyed by job_id) and consumed by the
/ws/screenshots/{job_id} WebSocket — mirrors how OSINT runs stream + post-process.

Jobs are durable rows, not an in-memory dict, because the REST call that
creates a job and the WebSocket that consumes it are two separate requests
that can land on two different uvicorn worker processes (docker-compose.prod.yml
runs 4) -- a module-level dict would only be visible to whichever process
happened to create it.
"""

import json
import os
import shlex
import shutil
import uuid
from datetime import datetime, timedelta

from database import SessionLocal, ScreenshotJob, engine

# How long an orphaned job (its WebSocket never connected -- browser tab
# closed, client crashed) sits in the registry before create_job() sweeps
# it. Without this, "Capture job not found or expired" was a lie: nothing
# ever expired, and jobs accumulated forever.
_JOB_EXPIRY = timedelta(hours=1)

# gowitness defaults to looking for a binary literally named "google-chrome",
# which doesn't exist on Debian (the backend image installs `chromium`
# instead) -- without --chrome-path every capture fails with
# `exec: "google-chrome": executable file not found in $PATH`.
_CHROME_CANDIDATES = ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable")


def _chrome_path() -> str | None:
    for name in _CHROME_CANDIDATES:
        path = shutil.which(name)
        if path:
            return path
    return None


def _data_dir() -> str:
    """Directory that holds the SQLite DB — screenshots live in a subfolder here."""
    db_path = engine.url.database or "./seraph.db"
    return os.path.abspath(os.path.dirname(db_path) or ".")


def screenshots_root() -> str:
    root = os.path.join(_data_dir(), "screenshots")
    os.makedirs(root, exist_ok=True)
    return root


def create_job(project_id: str, target_id: str | None, urls: list[str]) -> dict:
    """Register a capture job and return {job_id, command, outdir, urls}."""
    clean = [u.strip() for u in urls if u.strip()]
    if not clean:
        raise ValueError("No URLs supplied")

    job_id = str(uuid.uuid4())
    outdir = os.path.join(screenshots_root(), job_id)
    os.makedirs(outdir, exist_ok=True)

    urls_file = os.path.join(outdir, "urls.txt")
    with open(urls_file, "w") as fh:
        fh.write("\n".join(clean) + "\n")

    # gowitness v3 syntax: scan a file of URLs, write images to
    # --screenshot-path, and write one JSON line per result carrying the
    # exact file_name gowitness wrote plus its url/response_code/title --
    # index_results() reads this instead of trying to re-derive the
    # url<->image mapping from sorted filenames (which silently mismatched
    # rows whenever filename sort order didn't match request order).
    # --skip-html drops the (large, unused) HTML body from each result.
    results_file = os.path.join(outdir, "results.jsonl")
    command = (
        f"gowitness scan file -f {shlex.quote(urls_file)} "
        f"--screenshot-path {shlex.quote(outdir)} "
        f"--write-jsonl --write-jsonl-file {shlex.quote(results_file)} "
        f"--skip-html --timeout 15"
    )
    chrome_path = _chrome_path()
    if chrome_path:
        command += f" --chrome-path {shlex.quote(chrome_path)}"

    db = SessionLocal()
    try:
        # Sweep jobs whose WebSocket never connected before adding this one.
        cutoff = datetime.utcnow() - _JOB_EXPIRY
        db.query(ScreenshotJob).filter(ScreenshotJob.created_at < cutoff).delete(synchronize_session=False)
        db.add(ScreenshotJob(
            id=job_id,
            project_id=project_id,
            target_id=target_id,
            urls_json=json.dumps(clean),
            outdir=outdir,
            command=command,
        ))
        db.commit()
    finally:
        db.close()

    return {
        "job_id": job_id,
        "project_id": project_id,
        "target_id": target_id,
        "urls": clean,
        "outdir": outdir,
        "command": command,
    }


def get_job(job_id: str) -> dict | None:
    db = SessionLocal()
    try:
        row = db.query(ScreenshotJob).filter(ScreenshotJob.id == job_id).first()
        if not row:
            return None
        return {
            "job_id": row.id,
            "project_id": row.project_id,
            "target_id": row.target_id,
            "urls": json.loads(row.urls_json),
            "outdir": row.outdir,
            "command": row.command,
        }
    finally:
        db.close()


def index_results(job: dict) -> list[dict]:
    """Read gowitness's own --write-jsonl output and return rows to persist.

    Each JSONL row carries the exact file_name gowitness wrote for that
    capture, plus its url/response_code/title directly -- used instead of
    globbing the output directory and pairing images to requested URLs by
    sorted filename order, which silently mismatched url<->image whenever
    the sort order of gowitness's sanitized filenames didn't match the
    order URLs were requested in.
    """
    results_file = os.path.join(job["outdir"], "results.jsonl")
    rows: list[dict] = []
    if not os.path.exists(results_file):
        return rows

    with open(results_file) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                continue
            if result.get("failed") or not result.get("file_name"):
                continue
            image_path = os.path.join(job["outdir"], result["file_name"])
            if not os.path.exists(image_path):
                continue
            response_code = result.get("response_code")
            rows.append({
                "project_id": job["project_id"],
                "target_id": job.get("target_id"),
                "url": result.get("url") or "",
                "title": result.get("title") or "",
                "status_code": str(response_code) if response_code is not None else None,
                "image_path": os.path.abspath(image_path),
            })
    return rows


def finish_job(job_id: str) -> None:
    db = SessionLocal()
    try:
        db.query(ScreenshotJob).filter(ScreenshotJob.id == job_id).delete()
        db.commit()
    finally:
        db.close()
