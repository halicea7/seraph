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

import glob
import json
import os
import shlex
import shutil
import uuid

from database import SessionLocal, ScreenshotJob, engine

_IMAGE_EXTS = ("*.png", "*.jpeg", "*.jpg")

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

    # gowitness v3 syntax: scan a file of URLs, write images to --screenshot-path,
    # skip the results DB (--write-none). shlex.quote guards the paths.
    command = (
        f"gowitness scan file -f {shlex.quote(urls_file)} "
        f"--screenshot-path {shlex.quote(outdir)} --write-none --timeout 15"
    )
    chrome_path = _chrome_path()
    if chrome_path:
        command += f" --chrome-path {shlex.quote(chrome_path)}"

    db = SessionLocal()
    try:
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


def _url_from_filename(fname: str) -> str:
    """Best-effort reverse of gowitness' filename sanitization for display."""
    base = os.path.splitext(os.path.basename(fname))[0]
    return base.replace("---", "://").replace("-", ".")


def index_results(job: dict) -> list[dict]:
    """Glob the job output dir for images and return rows to persist.

    Pairs images with the requested URLs by sorted order when the counts match;
    otherwise derives a display URL from the (sanitized) filename.
    """
    images: list[str] = []
    for pattern in _IMAGE_EXTS:
        images.extend(glob.glob(os.path.join(job["outdir"], "**", pattern), recursive=True))
    images = sorted(set(images))

    urls = job["urls"]
    rows: list[dict] = []
    for i, path in enumerate(images):
        url = urls[i] if len(images) == len(urls) else _url_from_filename(path)
        rows.append({
            "project_id": job["project_id"],
            "target_id": job.get("target_id"),
            "url": url,
            "title": os.path.basename(path),
            "image_path": os.path.abspath(path),
        })
    return rows


def finish_job(job_id: str) -> None:
    db = SessionLocal()
    try:
        db.query(ScreenshotJob).filter(ScreenshotJob.id == job_id).delete()
        db.commit()
    finally:
        db.close()
