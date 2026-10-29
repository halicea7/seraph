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
    """Parse Set-Cookie response header(s) and upsert them into the jar."""
    if not set_cookie_values:
        return
    for raw in set_cookie_values:
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            continue
        for name, morsel in jar.items():
            cookie_domain = morsel["domain"].lstrip(".") or _strip_www(host)
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
                db.add(HttpCookie(project_id=project_id, domain=cookie_domain, name=name, value=morsel.value))
    db.commit()


def build_cookie_header(db, project_id: str, host: str) -> str:
    """Return a `Cookie:` header value for every jar entry matching host, or '' if none."""
    rows = db.query(HttpCookie).filter(HttpCookie.project_id == project_id).all()
    matches = [r for r in rows if _domains_match(host, r.domain)]
    if not matches:
        return ""
    return "; ".join(f"{r.name}={r.value}" for r in matches)
