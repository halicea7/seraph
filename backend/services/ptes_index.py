"""
PTES (Penetration Testing Execution Standard) knowledge index.

Fetches wiki content from pentest-standard.org via the MediaWiki API,
parses it into sections, and stores them in a SQLite FTS5 table for
semantic search / RAG injection into the AI Operator.

Table schema:
    ptes_sections(phase_id, phase_name, section, content, url)
    ptes_meta(key, value)   — last_sync, count
"""

import re
import sqlite3
import threading
from pathlib import Path

import requests

from config import settings

# ── Config ────────────────────────────────────────────────────────────────────

PTES_API = "http://www.pentest-standard.org/api.php"
PTES_BASE = "http://www.pentest-standard.org/index.php"

# (phase_id, display_name, wiki_page_title)
PTES_PAGES = [
    ("pre-engagement",    "Pre-Engagement",          "Pre-engagement"),
    ("intelligence",      "Intelligence Gathering",  "Intelligence_Gathering"),
    ("threat-modeling",   "Threat Modeling",         "Threat_Modeling"),
    ("vuln-analysis",     "Vulnerability Analysis",  "Vulnerability_Analysis"),
    ("exploitation",      "Exploitation",            "Exploitation"),
    ("post-exploitation", "Post Exploitation",       "Post_Exploitation"),
    ("reporting",         "Reporting",               "Reporting"),
    ("technical",         "Technical Guidelines",    "PTES_Technical_Guidelines"),
]

_DB_PATH = Path(settings.database_url.replace("sqlite:///", "")).parent / "ptes_index.db"
_sync_lock = threading.Lock()


# ── DB helpers ────────────────────────────────────────────────────────────────

def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(str(_DB_PATH))
    c.row_factory = sqlite3.Row
    return c


def ensure_fts_table() -> None:
    with _conn() as c:
        c.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS ptes_sections USING fts5(
                phase_id    UNINDEXED,
                phase_name  UNINDEXED,
                section     UNINDEXED,
                content,
                url         UNINDEXED,
                tokenize    = 'porter ascii'
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS ptes_meta (
                key   TEXT PRIMARY KEY,
                value TEXT
            )
        """)


# ── Wikitext parser ───────────────────────────────────────────────────────────

def _parse_sections(wikitext: str) -> list[tuple[str, str]]:
    """
    Split wikitext into (section_title, content) pairs.
    Top-level (=) becomes the phase intro; == and === become sub-sections.
    Strips wiki markup so stored text is plain.
    """
    # normalise line endings
    text = wikitext.replace("\r\n", "\n").replace("\r", "\n")

    # split on any heading line (=+ title =+)
    parts = re.split(r"^(={1,4}[^=\n]+={1,4})\s*$", text, flags=re.MULTILINE)

    sections: list[tuple[str, str]] = []
    # parts alternates: [pre-heading-text, heading, content, heading, content …]
    if parts[0].strip():
        sections.append(("Overview", parts[0]))

    for i in range(1, len(parts) - 1, 2):
        heading = parts[i].strip("= \t")
        content = parts[i + 1] if i + 1 < len(parts) else ""
        sections.append((heading, content))

    cleaned = []
    for title, body in sections:
        body = _strip_wiki(body)
        if len(body.strip()) < 40:   # skip near-empty sections
            continue
        cleaned.append((title, body[:3000]))   # cap per-section size
    return cleaned


def _strip_wiki(text: str) -> str:
    """Remove common wikitext markup, leaving readable plain text."""
    # [[link|display]] → display
    text = re.sub(r"\[\[(?:[^\]|]*\|)?([^\]]+)\]\]", r"\1", text)
    # [url display] → display
    text = re.sub(r"\[https?://\S+\s+([^\]]+)\]", r"\1", text)
    # bare external links
    text = re.sub(r"https?://\S+", "", text)
    # {{templates}}
    text = re.sub(r"\{\{[^}]*\}\}", "", text)
    # '''bold''' / ''italic''
    text = re.sub(r"'{2,3}", "", text)
    # HTML tags
    text = re.sub(r"<[^>]+>", "", text)
    # category / file lines
    text = re.sub(r"^\s*(?:Category|File|Image):.+$", "", text, flags=re.MULTILINE)
    # collapse whitespace
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


# ── Sync ─────────────────────────────────────────────────────────────────────

def _fetch_page(wiki_title: str) -> str | None:
    try:
        resp = requests.get(PTES_API, params={
            "action": "query",
            "titles": wiki_title,
            "prop": "revisions",
            "rvprop": "content",
            "format": "json",
        }, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        pages = data["query"]["pages"]
        page = next(iter(pages.values()))
        if "missing" in page:
            return None
        return page["revisions"][0]["*"]
    except Exception:
        return None


def _do_sync() -> None:
    ensure_fts_table()
    rows: list[tuple] = []
    for phase_id, phase_name, wiki_title in PTES_PAGES:
        wikitext = _fetch_page(wiki_title)
        if not wikitext:
            continue
        sections = _parse_sections(wikitext)
        url = f"{PTES_BASE}/{wiki_title}"
        for section_title, content in sections:
            rows.append((phase_id, phase_name, section_title, content, url))

    with _conn() as c:
        c.execute("DELETE FROM ptes_sections")
        c.executemany(
            "INSERT INTO ptes_sections(phase_id, phase_name, section, content, url) VALUES (?,?,?,?,?)",
            rows,
        )
        from datetime import datetime
        c.execute("INSERT OR REPLACE INTO ptes_meta VALUES ('last_sync', ?)", (datetime.utcnow().isoformat(),))
        c.execute("INSERT OR REPLACE INTO ptes_meta VALUES ('count', ?)", (str(len(rows)),))


def sync(background: bool = False) -> None:
    if background:
        t = threading.Thread(target=_run_sync, daemon=True)
        t.start()
    else:
        _run_sync()


def _run_sync() -> None:
    try:
        _sync_lock.acquire()
        _do_sync()
    finally:
        _sync_lock.release()


def sync_if_empty() -> None:
    try:
        ensure_fts_table()
        with _conn() as c:
            row = c.execute("SELECT value FROM ptes_meta WHERE key='count'").fetchone()
            count = int(row["value"]) if row else 0
        if count == 0:
            sync(background=True)
    except Exception:
        pass


# ── Query ─────────────────────────────────────────────────────────────────────

def get_status() -> dict:
    try:
        ensure_fts_table()
        with _conn() as c:
            count_row = c.execute("SELECT value FROM ptes_meta WHERE key='count'").fetchone()
            sync_row  = c.execute("SELECT value FROM ptes_meta WHERE key='last_sync'").fetchone()
        return {
            "count":     int(count_row["value"]) if count_row else 0,
            "last_sync": sync_row["value"] if sync_row else None,
            "syncing":   not _sync_lock.acquire(blocking=False),
        }
    except Exception:
        return {"count": 0, "last_sync": None, "syncing": False}
    finally:
        try:
            _sync_lock.release()
        except RuntimeError:
            pass


def search(query: str, limit: int = 3) -> list[dict]:
    """FTS5 keyword search over PTES section content."""
    try:
        ensure_fts_table()
        safe = re.sub(r'[^\w\s]', ' ', query).strip()
        if not safe:
            return []
        with _conn() as c:
            rows = c.execute(
                """SELECT phase_id, phase_name, section, content, url,
                          bm25(ptes_sections) AS score
                   FROM ptes_sections
                   WHERE ptes_sections MATCH ?
                   ORDER BY score
                   LIMIT ?""",
                (safe, limit),
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


def get_by_phase(phase_id: str) -> list[dict]:
    try:
        ensure_fts_table()
        with _conn() as c:
            rows = c.execute(
                "SELECT * FROM ptes_sections WHERE phase_id = ?", (phase_id,)
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []
