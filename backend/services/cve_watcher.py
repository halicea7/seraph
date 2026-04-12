"""
CVE Watcher — queries the NVD API for known vulnerabilities affecting
services detected during auto-probe nmap scans.

On first detection a WatchedService row is created. The daily scheduler job
calls check_all_watched_services() which queries NVD for each entry and
creates a Notification + Finding when new CVEs are found.

NVD free tier: 5 requests / 30 s. We sleep 7 s between requests to stay safe.
"""

import asyncio
import json
import re
import urllib.request
import urllib.parse
import uuid
from datetime import datetime
from typing import Optional


_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


# ── NVD query ─────────────────────────────────────────────────────────────────

def _fetch_nvd_cves(keyword: str) -> list[dict]:
    """Synchronous NVD keyword search. Returns list of CVE item dicts."""
    params = urllib.parse.urlencode({
        "keywordSearch": keyword,
        "resultsPerPage": 20,
        "noRejected": "",
    })
    url = f"{_NVD_URL}?{params}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Seraph/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("vulnerabilities", [])
    except Exception:
        return []


def _extract_cve_ids(items: list[dict]) -> list[str]:
    return [
        item["cve"]["id"]
        for item in items
        if "cve" in item and "id" in item["cve"]
    ]


def _cve_severity(items: list[dict], cve_id: str) -> str:
    for item in items:
        if item.get("cve", {}).get("id") == cve_id:
            metrics = item["cve"].get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                ms = metrics.get(key, [])
                if ms:
                    score = ms[0].get("cvssData", {}).get("baseSeverity", "")
                    if score:
                        return score.lower()
    return "medium"


# ── Populate watched services after nmap ─────────────────────────────────────

def populate_watched_services(target_id: str, service_terms: list[str]) -> None:
    """Upsert WatchedService rows for service_terms found on target_id."""
    from database import SessionLocal, WatchedService

    if not service_terms:
        return
    db = SessionLocal()
    try:
        existing = {
            ws.service_term
            for ws in db.query(WatchedService)
            .filter(WatchedService.target_id == target_id)
            .all()
        }
        for term in service_terms:
            if term not in existing:
                db.add(WatchedService(
                    id=str(uuid.uuid4()),
                    target_id=target_id,
                    service_term=term,
                ))
        db.commit()
    finally:
        db.close()


# ── Per-service CVE check ─────────────────────────────────────────────────────

async def check_service(watched_id: str) -> int:
    """
    Query NVD for one WatchedService, persist new CVEs, fire notifications.
    Returns count of new CVEs found.
    """
    from database import SessionLocal, WatchedService, Finding, Notification, Scan, Target
    from services.webhook_service import fire_webhooks

    db = SessionLocal()
    try:
        ws = db.query(WatchedService).filter(WatchedService.id == watched_id).first()
        if not ws:
            return 0
        term = ws.service_term
        target_id = ws.target_id
        known: list[str] = json.loads(ws.known_cves or "[]")
    finally:
        db.close()

    # NVD query in thread so we don't block the event loop
    items = await asyncio.to_thread(_fetch_nvd_cves, term)
    found_ids = _extract_cve_ids(items)
    new_ids = [c for c in found_ids if c not in known]

    if not new_ids:
        db = SessionLocal()
        try:
            ws = db.query(WatchedService).filter(WatchedService.id == watched_id).first()
            if ws:
                ws.last_checked = datetime.utcnow()
                db.commit()
        finally:
            db.close()
        return 0

    # Find the most recent nmap scan for this target to attach findings to
    db = SessionLocal()
    try:
        ws = db.query(WatchedService).filter(WatchedService.id == watched_id).first()
        if not ws:
            return 0

        scan = (
            db.query(Scan)
            .filter(Scan.target_id == target_id, Scan.scan_type == "nmap")
            .order_by(Scan.completed_at.desc())
            .first()
        )
        target = db.query(Target).filter(Target.id == target_id).first()
        target_label = target.hostname_or_ip if target else target_id

        for cve_id in new_ids:
            severity = _cve_severity(items, cve_id)
            if scan:
                db.add(Finding(
                    id=str(uuid.uuid4()),
                    scan_id=scan.id,
                    severity=severity,
                    title=f"{cve_id} affects {term}",
                    description=(
                        f"CVE watchlist detected {cve_id} matching '{term}' "
                        f"on {target_label}. Sourced from NVD."
                    ),
                    cve_id=cve_id,
                    remediation="Review the CVE on https://nvd.nist.gov and apply vendor patches.",
                ))

        updated_known = known + new_ids
        ws.known_cves = json.dumps(updated_known)
        ws.last_checked = datetime.utcnow()

        notif_type = "critical" if any(
            _cve_severity(items, c) in ("critical", "high") for c in new_ids
        ) else "warning"

        n = Notification(
            id=str(uuid.uuid4()),
            title=f"CVE Watch: {len(new_ids)} new CVE(s) for {term}",
            body=f"New: {', '.join(new_ids[:5])}" + (" …" if len(new_ids) > 5 else ""),
            type=notif_type,
            scan_id=scan.id if scan else None,
        )
        db.add(n)
        db.commit()
    finally:
        db.close()

    asyncio.create_task(fire_webhooks(
        notif_type,
        f"CVE Watch: {len(new_ids)} new CVE(s) for {term}",
        f"New on {target_label}: {', '.join(new_ids[:5])}",
    ))

    return len(new_ids)


# ── Daily bulk check ──────────────────────────────────────────────────────────

async def check_all_watched_services() -> None:
    """Scheduled job: check every WatchedService, rate-limited to NVD free tier."""
    from database import SessionLocal, WatchedService

    db = SessionLocal()
    try:
        ids = [ws.id for ws in db.query(WatchedService).all()]
    finally:
        db.close()

    for idx, wid in enumerate(ids):
        if idx > 0:
            await asyncio.sleep(7)  # stay within 5 req/30 s NVD free tier
        try:
            await check_service(wid)
        except Exception:
            pass
