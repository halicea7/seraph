"""
Per-project cookie jar for the HTTP Request Workbench.

Seeded automatically from a response's Set-Cookie headers -- logging in once
on a target keeps every subsequent repeater/fuzz request authenticated
without hand-copying a Cookie header out of devtools. Attached automatically
to outgoing requests unless the request already sets its own Cookie header
(an explicit header always wins). Domain matching is suffix-based (good
enough for a pentesting tool, not a full RFC 6265 implementation) so a
cookie set by app.corp.local also applies when the Workbench targets
sub.app.corp.local or vice versa.
"""

from datetime import datetime
from http.cookies import SimpleCookie

from database import HttpCookie


def _strip_www(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def _domains_match(request_domain: str, cookie_domain: str) -> bool:
    a, b = _strip_www(request_domain), _strip_www(cookie_domain)
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def ingest_set_cookie(db, project_id: str, host: str, set_cookie_values: list[str]) -> None:
    """Parse Set-Cookie response header(s) and upsert them into the jar.

    SessionLocal is created with autoflush=False (database.py), so a
    db.query(...).first() lookup here does NOT see an earlier db.add() from
    the same call until a flush/commit happens -- a response that sets the
    same cookie name more than once (PHP regenerating the session mid-request
    is common) re-queried "does this row exist yet?" against a session that
    hadn't actually written it yet, and inserted a fresh duplicate row every
    time instead of updating the one it had just added. Tracking rows
    in-memory for the duration of this call sidesteps the flush timing
    entirely instead of relying on it.
    """
    if not set_cookie_values:
        return
    seen: dict[tuple[str, str], HttpCookie] = {}
    for raw in set_cookie_values:
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            continue
        for name, morsel in jar.items():
            cookie_domain = morsel["domain"].lstrip(".") or _strip_www(host)
            key = (cookie_domain, name)
            row = seen.get(key)
            if row is None:
                row = (
                    db.query(HttpCookie)
                    .filter(
                        HttpCookie.project_id == project_id,
                        HttpCookie.domain == cookie_domain,
                        HttpCookie.name == name,
                    )
                    .first()
                )
            if row:
                row.value = morsel.value
                row.updated_at = datetime.utcnow()
            else:
                row = HttpCookie(project_id=project_id, domain=cookie_domain, name=name, value=morsel.value)
                db.add(row)
            seen[key] = row
    db.commit()


def build_cookie_header(db, project_id: str, host: str) -> str:
    """Return a `Cookie:` header value for every jar entry matching host, or '' if none."""
    rows = db.query(HttpCookie).filter(HttpCookie.project_id == project_id).all()
    matches = [r for r in rows if _domains_match(host, r.domain)]
    if not matches:
        return ""
    return "; ".join(f"{r.name}={r.value}" for r in matches)
