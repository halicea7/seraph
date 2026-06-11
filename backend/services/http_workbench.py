"""
HTTP Request Workbench — send/replay and parameter fuzzing.

Uses httpx (already a dependency, see services/nessus.py) to send a single
request or fuzz a §FUZZ§ marker across a payload list. Fuzz runs are held in a
small in-memory registry and streamed over /ws/httpfuzz/{run_id}, mirroring the
screenshot/OSINT streaming pattern.
"""

import time
import uuid

import httpx

MARKER = "§FUZZ§"
MAX_PAYLOADS = 5000
MAX_BODY_CHARS = 200_000

_FUZZ_JOBS: dict[str, dict] = {}


async def send_request(
    method: str,
    url: str,
    headers: dict | None,
    body: str,
    timeout: float = 20.0,
) -> dict:
    """Send one request and return a structured response summary."""
    t0 = time.perf_counter()
    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=timeout) as client:
        resp = await client.request(
            method.upper(),
            url,
            headers=headers or None,
            content=body.encode() if body else None,
        )
    elapsed = (time.perf_counter() - t0) * 1000
    return {
        "status": resp.status_code,
        "reason": resp.reason_phrase,
        "headers": dict(resp.headers),
        "body": resp.text[:MAX_BODY_CHARS],
        "size": len(resp.content),
        "elapsed_ms": round(elapsed, 1),
    }


def _apply(template: str | None, payload: str) -> str | None:
    return template.replace(MARKER, payload) if template else template


def create_fuzz_job(
    method: str,
    url: str,
    headers: dict | None,
    body: str,
    payloads: list[str],
) -> dict:
    """Register a fuzz job. Returns {run_id, count}."""
    clean = [p for p in (payloads or []) if p != ""][:MAX_PAYLOADS]
    if not clean:
        raise ValueError("No payloads supplied")
    if MARKER not in (url + (body or "") + "".join((headers or {}).values())):
        raise ValueError(f"No {MARKER} marker found in the request to fuzz")

    run_id = str(uuid.uuid4())
    _FUZZ_JOBS[run_id] = {
        "run_id": run_id,
        "method": method,
        "url": url,
        "headers": headers or {},
        "body": body or "",
        "payloads": clean,
    }
    return {"run_id": run_id, "count": len(clean)}


def get_fuzz_job(run_id: str) -> dict | None:
    return _FUZZ_JOBS.get(run_id)


def finish_fuzz_job(run_id: str) -> None:
    _FUZZ_JOBS.pop(run_id, None)


async def run_fuzz(job: dict, timeout: float = 15.0):
    """Yield a result dict per payload: {index, payload, status, size, elapsed_ms}."""
    headers_tmpl = job["headers"]
    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=timeout) as client:
        for i, payload in enumerate(job["payloads"]):
            url = _apply(job["url"], payload)
            body = _apply(job["body"], payload)
            headers = {k: _apply(v, payload) for k, v in headers_tmpl.items()}
            t0 = time.perf_counter()
            try:
                resp = await client.request(
                    job["method"].upper(),
                    url,
                    headers=headers or None,
                    content=body.encode() if body else None,
                )
                yield {
                    "index": i,
                    "payload": payload,
                    "status": resp.status_code,
                    "size": len(resp.content),
                    "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
                }
            except Exception as exc:  # network errors shouldn't kill the run
                yield {
                    "index": i,
                    "payload": payload,
                    "status": 0,
                    "size": 0,
                    "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
                    "error": str(exc)[:120],
                }
