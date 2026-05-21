"""
MITRE ATT&CK ingestion and SQLite FTS5 index.

On first run (or manual sync), downloads the Enterprise ATT&CK STIX bundle
from MITRE's public GitHub repo, parses attack-pattern objects, and loads
them into an FTS5 virtual table for fast keyword search.

Usage:
    from services.attack_index import ensure_fts_table, sync, search, get_by_id
"""

import json
import logging
import re
import sqlite3
import threading
import urllib.request
from datetime import datetime

log = logging.getLogger(__name__)

STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

_sync_lock = threading.Lock()
_sync_state: dict = {"state": "idle", "error": None}


# ── DB helpers ────────────────────────────────────────────────────────────────

def _db_path() -> str:
    from database import engine
    return engine.url.database  # e.g. "/app/data/seraph.db"


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(_db_path(), check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


# ── Schema ────────────────────────────────────────────────────────────────────

def ensure_fts_table() -> None:
    """Create the FTS5 table and metadata table if they don't exist."""
    with _conn() as c:
        c.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS attack_techniques USING fts5(
                technique_id UNINDEXED,
                name,
                tactic      UNINDEXED,
                platforms   UNINDEXED,
                description,
                detection,
                url         UNINDEXED
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS attack_meta (
                key   TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        c.commit()


# ── Status ────────────────────────────────────────────────────────────────────

def get_status() -> dict:
    try:
        with _conn() as c:
            count     = c.execute("SELECT COUNT(*) FROM attack_techniques").fetchone()[0]
            row       = c.execute("SELECT value FROM attack_meta WHERE key='last_sync'").fetchone()
            last_sync = row[0] if row else None
        return {"count": count, "last_sync": last_sync, **_sync_state}
    except Exception:
        return {"count": 0, "last_sync": None, **_sync_state}


# ── Parsing ───────────────────────────────────────────────────────────────────

def _parse_stix(bundle: dict) -> list[dict]:
    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        technique_id = url = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                url          = ref.get("url", "")
                break

        if not technique_id:
            continue

        tactics = [
            p["phase_name"]
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]

        techniques.append({
            "technique_id": technique_id,
            "name":         obj.get("name", ""),
            "tactic":       ", ".join(tactics),
            "platforms":    ", ".join(obj.get("x_mitre_platforms", [])),
            "description":  (obj.get("description", "") or "")[:2000],
            "detection":    (obj.get("x_mitre_detection", "") or "")[:1000],
            "url":          url,
        })

    return techniques


# ── Sync ──────────────────────────────────────────────────────────────────────

def sync(background: bool = False) -> None:
    """Download and index the ATT&CK dataset.

    Pass background=True to run in a daemon thread (non-blocking).
    Silently skips if a sync is already in progress.
    """
    if background:
        threading.Thread(target=sync, daemon=True).start()
        return

    if not _sync_lock.acquire(blocking=False):
        log.info("ATT&CK sync already in progress — skipping")
        return

    global _sync_state
    try:
        _sync_state = {"state": "downloading", "error": None}
        log.info("Downloading ATT&CK STIX bundle from MITRE CTI GitHub…")

        req = urllib.request.Request(STIX_URL, headers={"User-Agent": "Seraph/2.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read()

        _sync_state = {"state": "parsing", "error": None}
        techniques = _parse_stix(json.loads(raw))
        log.info("Parsed %d ATT&CK techniques", len(techniques))

        _sync_state = {"state": "indexing", "error": None}
        with _conn() as c:
            c.execute("DELETE FROM attack_techniques")
            c.executemany(
                "INSERT INTO attack_techniques VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (t["technique_id"], t["name"], t["tactic"], t["platforms"],
                     t["description"], t["detection"], t["url"])
                    for t in techniques
                ],
            )
            now = datetime.utcnow().isoformat()
            c.execute("INSERT OR REPLACE INTO attack_meta VALUES ('last_sync', ?)", (now,))
            c.commit()

        _sync_state = {"state": "idle", "error": None}
        log.info("ATT&CK index ready — %d techniques", len(techniques))

    except Exception as exc:
        log.error("ATT&CK sync failed: %s", exc)
        _sync_state = {"state": "error", "error": str(exc)}
    finally:
        _sync_lock.release()


def sync_if_empty() -> None:
    """Trigger a background sync only if the index has no techniques."""
    try:
        with _conn() as c:
            count = c.execute("SELECT COUNT(*) FROM attack_techniques").fetchone()[0]
        if count == 0:
            log.info("ATT&CK index is empty — starting background sync")
            sync(background=True)
    except Exception:
        sync(background=True)


# ── Search ────────────────────────────────────────────────────────────────────

def _sanitize(query: str) -> str:
    """Escape FTS5 special characters and wrap tokens for prefix matching."""
    # Replace punctuation (except hyphens) with spaces
    cleaned = re.sub(r'[^\w\s\-]', ' ', query).strip()
    if not cleaned:
        return ""
    # Quote each token so FTS5 treats them as phrase terms
    tokens = [f'"{t}"' for t in cleaned.split() if t]
    return " ".join(tokens)


def search(query: str, limit: int = 5) -> list[dict]:
    """Keyword search across name, description, and detection fields.

    If the query looks like a T-ID (e.g. T1003, T1003.001), does a direct
    lookup first. Otherwise runs an FTS5 MATCH query.
    """
    query = query.strip()
    if not query:
        return []

    # Direct T-ID lookup
    if re.match(r'^T\d{4}(\.\d{3})?$', query, re.IGNORECASE):
        result = get_by_id(query)
        return [result] if result else []

    safe = _sanitize(query)
    if not safe:
        return []

    try:
        with _conn() as c:
            rows = c.execute(
                """
                SELECT technique_id, name, tactic, platforms, description, detection, url
                FROM attack_techniques
                WHERE attack_techniques MATCH ?
                ORDER BY rank
                LIMIT ?
                """,
                (safe, limit),
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception as exc:
        log.warning("ATT&CK search error: %s", exc)
        return []


def get_by_id(technique_id: str) -> dict | None:
    """Direct lookup by technique ID (case-insensitive)."""
    try:
        with _conn() as c:
            row = c.execute(
                "SELECT * FROM attack_techniques WHERE technique_id = ?",
                (technique_id.upper(),),
            ).fetchone()
        return dict(row) if row else None
    except Exception:
        return None


def get_by_tactic(tactic: str, limit: int = 20) -> list[dict]:
    """Return techniques for a given tactic (e.g. 'lateral-movement')."""
    try:
        with _conn() as c:
            rows = c.execute(
                "SELECT * FROM attack_techniques WHERE tactic LIKE ? LIMIT ?",
                (f"%{tactic}%", limit),
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []
