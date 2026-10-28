"""Regression tests for the security/correctness fix pass (security-correctness-fixes branch).

Each test targets one specific fix called out in the audit/review docs and
the approved plan. Run alongside the smoke suite:  cd backend && pytest tests -q
"""

import json

import pytest

import database
from database import Finding, Scan, HardeningReport

# Reuse the smoke suite's app/db/auth fixtures (same TestClient, same admin
# user, same seeded project) rather than standing up a second app instance.
from test_smoke import client, auth, pid  # noqa: F401

PW = "Passw0rdTest1"


@pytest.fixture(scope="session")
def analyst_auth(client, auth):
    """A second, non-admin user — the `auth` fixture's "smoke" user is the
    first-run admin, so role-gated routes need a distinct analyst account."""
    r = client.post(
        "/api/v1/auth/users",
        json={"username": "analyst1", "password": PW, "role": "analyst"},
        headers=auth,
    )
    assert r.status_code == 201, r.text
    r = client.post("/api/v1/auth/login", data={"username": "analyst1", "password": PW})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# ── C.12 — credential secrets never ride along on the list endpoint ──────────

def test_credentials_list_never_contains_secret(client, auth, pid):
    r = client.post(
        "/api/v1/credentials",
        json={"project_id": pid, "username": "root", "secret": "sup3rs3cr3t", "cred_type": "password"},
        headers=auth,
    )
    assert r.status_code == 201, r.text
    cred_id = r.json()["id"]
    assert "secret" not in r.json()

    r = client.get(f"/api/v1/credentials?project_id={pid}", headers=auth)
    assert r.status_code == 200
    rows = r.json()
    assert any(c["id"] == cred_id for c in rows)
    for c in rows:
        assert "secret" not in c
    found = next(c for c in rows if c["id"] == cred_id)
    assert found["has_secret"] is True

    # The plaintext is still retrievable, but only via the explicit, audited reveal route.
    r = client.post(f"/api/v1/credentials/{cred_id}/reveal", headers=auth)
    assert r.status_code == 200
    assert r.json()["secret"] == "sup3rs3cr3t"


# ── B.8 — retest guard rejects empty/foreign/incomplete scan_id ──────────────

def test_retest_rejects_missing_and_foreign_scan(client, auth, pid):
    # Build a target + a completed scan with a real finding.
    r = client.post(
        f"/api/v1/projects/{pid}/targets",
        json={"hostname_or_ip": "10.0.0.9", "target_type": "linux_host"},
        headers=auth,
    )
    target_id = r.json()["id"]

    scan = Scan(
        target_id=target_id,
        scan_type="network_discovery",
        module="audit",
        status="completed",
        config_json='{"categories": [{"category_id": "network_discovery"}]}',
        raw_output="Nmap scan report for 10.0.0.9\n21/tcp open ftp vsftpd 3.0.3\n",
    )
    db = database.SessionLocal()
    try:
        db.add(scan)
        db.commit()
        from services.scan_lifecycle import save_parsed_findings
        all_current, _ = save_parsed_findings(db, scan, scan.raw_output)
        assert all_current
        finding_id = all_current[0].id
    finally:
        db.close()

    # Empty scan_id -> 400, not a silent "remediated".
    r = client.post(f"/api/v1/findings/{finding_id}/retest/evaluate", json={"scan_id": ""}, headers=auth)
    assert r.status_code == 400, r.text

    # Nonexistent scan_id -> 400.
    r = client.post(f"/api/v1/findings/{finding_id}/retest/evaluate", json={"scan_id": "does-not-exist"}, headers=auth)
    assert r.status_code == 400, r.text

    # A scan against a *different* target -> 400 (not silently marked remediated).
    r = client.post(
        f"/api/v1/projects/{pid}/targets",
        json={"hostname_or_ip": "10.0.0.10", "target_type": "linux_host"},
        headers=auth,
    )
    other_target_id = r.json()["id"]
    other_scan = Scan(target_id=other_target_id, scan_type="network_discovery", module="audit", status="completed")
    db = database.SessionLocal()
    try:
        db.add(other_scan)
        db.commit()
        other_scan_id = other_scan.id
    finally:
        db.close()
    r = client.post(f"/api/v1/findings/{finding_id}/retest/evaluate", json={"scan_id": other_scan_id}, headers=auth)
    assert r.status_code == 400, r.text

    # Finding must still be open — none of the bad calls above flipped it.
    db = database.SessionLocal()
    try:
        f = db.query(Finding).filter(Finding.id == finding_id).first()
        assert f.status == "open"
    finally:
        db.close()


# ── B.9 — rescan upserts by fingerprint, preserving triage ───────────────────

def test_rescan_preserves_triage_on_same_finding(client, auth, pid):
    r = client.post(
        f"/api/v1/projects/{pid}/targets",
        json={"hostname_or_ip": "10.0.0.20", "target_type": "linux_host"},
        headers=auth,
    )
    target_id = r.json()["id"]
    raw = "Nmap scan report for 10.0.0.20\n23/tcp open telnet\n"

    scan = Scan(target_id=target_id, scan_type="network_discovery", module="audit", status="completed", raw_output=raw)
    db = database.SessionLocal()
    try:
        db.add(scan)
        db.commit()
        scan_id = scan.id
        from services.scan_lifecycle import save_parsed_findings
        all_current, new_count = save_parsed_findings(db, scan, raw)
        assert len(all_current) == 1 and new_count == 1
        fid = all_current[0].id
        # Analyst triages it.
        f = db.query(Finding).filter(Finding.id == fid).first()
        f.status = "accepted"
        f.tags = "reviewed"
        db.commit()
    finally:
        db.close()

    # Re-parse the exact same output against the same scan_id (e.g. clicking
    # "Run on Server" again, or /audit/scans/{id}/parse twice).
    db = database.SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        from services.scan_lifecycle import save_parsed_findings
        all_current, new_count = save_parsed_findings(db, scan, raw)
        assert len(all_current) == 1, "must not duplicate the finding"
        assert new_count == 0, "must not count the existing finding as new"
        assert all_current[0].id == fid
        assert all_current[0].status == "accepted", "status must survive a rescan"
        assert all_current[0].tags == "reviewed", "tags must survive a rescan"
    finally:
        db.close()


# ── scan_lifecycle — target-scoped dedup (auto-probe/playbook/CIS-CAT) ───────

def test_upsert_findings_dedupes_across_scans_for_same_target(client, auth, pid):
    """Auto-probe, playbooks, and CIS-CAT import each create a brand-new Scan
    row per run — upsert_findings(dedupe_by_target=True) must dedupe against
    every scan for the target, not just the current one, or re-running the
    same tool would pile up duplicate findings indefinitely."""
    r = client.post(
        f"/api/v1/projects/{pid}/targets",
        json={"hostname_or_ip": "10.0.0.31", "target_type": "linux_host"},
        headers=auth,
    )
    target_id = r.json()["id"]

    from services.output_parser import ParsedFinding
    from services.scan_lifecycle import upsert_findings

    pf = ParsedFinding(title="Open port 22/tcp (ssh)", description="d", severity="info")

    db = database.SessionLocal()
    try:
        scan1 = Scan(target_id=target_id, scan_type="network_discovery", module="audit", status="completed")
        db.add(scan1)
        db.commit()
        all_current, new_count = upsert_findings(db, scan1, [pf], dedupe_by_target=True)
        assert new_count == 1
        fid = all_current[0].id

        # A second, brand-new Scan row for the same target — same tool re-run.
        scan2 = Scan(target_id=target_id, scan_type="network_discovery", module="audit", status="completed")
        db.add(scan2)
        db.commit()
        all_current, new_count = upsert_findings(db, scan2, [pf], dedupe_by_target=True)
        assert new_count == 0, "must not duplicate across scans for the same target"
        assert all_current[0].id == fid
        assert all_current[0].scan_id == scan1.id, "existing row must not be reassigned to the new scan"
    finally:
        db.close()


# ── A.1 — /ws/execute ignores client-supplied script, regenerates server-side ─

def test_ws_execute_ignores_client_script(client, auth, pid):
    r = client.post(
        f"/api/v1/projects/{pid}/targets",
        json={"hostname_or_ip": "10.0.0.30", "target_type": "linux_host"},
        headers=auth,
    )
    target_id = r.json()["id"]
    r = client.post(
        "/api/v1/audit/generate",
        json={
            "project_id": pid,
            "target_id": target_id,
            "scan_categories": [{"category_id": "network_discovery", "config": {}}],
        },
        headers=auth,
    )
    assert r.status_code == 200, r.text
    scan_id = r.json()["scan_id"]
    server_script = r.json()["script"]
    assert "10.0.0.30" in server_script

    token = auth["Authorization"].split(" ", 1)[1]
    with client.websocket_connect(f"/ws/execute/{scan_id}?token={token}") as ws:
        ws.send_json({"action": "run", "script": "echo I-AM-NOT-THE-SERVER-SCRIPT; rm -rf /"})
        msg = ws.receive_json()
        # First message should reflect the server-regenerated nmap script
        # being logged/executed, never the attacker-supplied one. We can't
        # run nmap in CI, so just assert the connection didn't echo our
        # injected payload as the thing that ran — i.e. no stdout line
        # contains our marker string.
        seen_marker = False
        for _ in range(20):
            if msg.get("type") == "exit":
                break
            if msg.get("type") in ("stdout", "stderr") and "I-AM-NOT-THE-SERVER-SCRIPT" in msg.get("data", ""):
                seen_marker = True
            msg = ws.receive_json()
        assert not seen_marker


# ── C.21 — delete_project requires admin; B.10 — no IntegrityError on delete ──

def test_delete_project_requires_admin_and_cleans_hardening_reports(client, auth, analyst_auth, pid):
    # Give the project a HardeningReport row (no ondelete at the DB level —
    # this is exactly what used to make delete_project fail once SQLite FK
    # enforcement was turned on, if it weren't cleaned up explicitly).
    db = database.SessionLocal()
    try:
        r = client.post(
            f"/api/v1/projects/{pid}/targets",
            json={"hostname_or_ip": "10.0.0.40", "target_type": "linux_host"},
            headers=auth,
        )
        target_id = r.json()["id"]
        db.add(HardeningReport(project_id=pid, target_id=target_id, profile="cis_l1"))
        db.commit()
    finally:
        db.close()

    # Analyst (non-admin) cannot delete the project.
    r = client.delete(f"/api/v1/projects/{pid}", headers=analyst_auth)
    assert r.status_code == 403, r.text

    # Admin can — and it doesn't 500 on the HardeningReport FK.
    r = client.delete(f"/api/v1/projects/{pid}", headers=auth)
    assert r.status_code == 204, r.text


# ── C.16 — CORS no longer reflects an arbitrary Origin ────────────────────────

def test_cors_does_not_reflect_arbitrary_origin(client, auth):
    r = client.get(
        "/api/v1/projects",
        headers={**auth, "Origin": "https://evil.example"},
    )
    assert r.headers.get("access-control-allow-origin") != "https://evil.example"


# ── C.14 — cracking run rejects out-of-allowlist hash_type / attack_mode ─────

def test_cracking_run_rejects_bad_hash_type_and_attack_mode(client, auth):
    r = client.post(
        "/api/v1/cracking/run",
        json={"tool": "hashcat", "hashes": ["aaa"], "hash_type": "0; rm -rf /", "attack_mode": "0"},
        headers=auth,
    )
    assert r.status_code in (400, 422), r.text

    r = client.post(
        "/api/v1/cracking/run",
        json={"tool": "hashcat", "hashes": ["aaa"], "hash_type": "0", "attack_mode": "99"},
        headers=auth,
    )
    assert r.status_code in (400, 422), r.text


# ── C.19 — SSRF guard rejects link-local / private addresses ─────────────────

def test_ai_config_rejects_link_local_endpoint(client, auth):
    r = client.put(
        "/api/v1/ai/config",
        json={"endpoint": "http://169.254.169.254/", "model": "x"},
        headers=auth,
    )
    assert r.status_code == 400, r.text


def test_webhook_rejects_private_url(client, auth):
    r = client.post(
        "/api/v1/webhooks",
        json={"name": "x", "url": "http://127.0.0.1:9999/hook", "events": ["critical"]},
        headers=auth,
    )
    assert r.status_code == 400, r.text


# ── Data integrity — duplicate hostname rejected within a project ───────────
# Uses its own project rather than the shared `pid` fixture: the preceding
# test in this file deletes the `pid` project, and this one runs after it.

def test_create_target_rejects_duplicate_hostname_in_project(client, auth):
    r = client.post("/api/v1/projects", json={"name": "dup-hostname-test-project-1"}, headers=auth)
    assert r.status_code == 201, r.text
    project_id = r.json()["id"]

    r = client.post(
        f"/api/v1/projects/{project_id}/targets",
        json={"hostname_or_ip": "10.0.0.50", "target_type": "linux_host"},
        headers=auth,
    )
    assert r.status_code == 201, r.text

    r = client.post(
        f"/api/v1/projects/{project_id}/targets",
        json={"hostname_or_ip": "10.0.0.50", "target_type": "linux_host"},
        headers=auth,
    )
    assert r.status_code == 400, r.text

    # A second project may still use the same hostname.
    r = client.post("/api/v1/projects", json={"name": "dup-hostname-test-project-2"}, headers=auth)
    assert r.status_code == 201, r.text
    other_pid = r.json()["id"]
    r = client.post(
        f"/api/v1/projects/{other_pid}/targets",
        json={"hostname_or_ip": "10.0.0.50", "target_type": "linux_host"},
        headers=auth,
    )
    assert r.status_code == 201, r.text


# ── Data integrity — terminating a cloud C2 instance deletes the row ────────

def test_terminate_cloud_instance_deletes_row(client, auth):
    """terminate_instance used to only set status='terminated' and never
    delete the row -- a "delete" that didn't delete. instance_id is left
    unset here so the AWS termination call is skipped entirely (the
    `if inst.instance_id:` guard in the route), isolating the DB-row fix."""
    from database import CloudC2Instance

    db = database.SessionLocal()
    try:
        inst = CloudC2Instance(name="t1", region="us-east-1")
        db.add(inst)
        db.commit()
        inst_id = inst.id
    finally:
        db.close()

    r = client.delete(f"/api/v1/cloud/instances/{inst_id}", headers=auth)
    assert r.status_code == 200, r.text

    db = database.SessionLocal()
    try:
        assert db.query(CloudC2Instance).filter(CloudC2Instance.id == inst_id).first() is None
    finally:
        db.close()


# ── check_scope fails closed on a corrupted scope_json, open on absent/empty ─

def test_check_scope_fails_closed_on_parse_error_only():
    from services.scope_service import check_scope

    # Absent or empty-include scope stays open -- "no scope configured".
    assert check_scope("10.0.0.5", None) == (True, "")
    assert check_scope("10.0.0.5", "") == (True, "")
    assert check_scope("10.0.0.5", '{"include": []}') == (True, "")

    # Corrupted JSON on an *existing* scope_json fails closed instead of
    # silently treating every target as in-scope.
    in_scope, reason = check_scope("10.0.0.5", "{not valid json")
    assert in_scope is False
    assert reason


# ── routers/demo.py is off by default ────────────────────────────────────────

def test_demo_router_not_registered_by_default(client, auth):
    r = client.get("/api/v1/demo/status", headers=auth)
    assert r.status_code == 404


# ── Unhandled exceptions get the same {"detail": ...} envelope as the rest ──

def test_unhandled_exception_returns_consistent_envelope(client, auth):
    """A route that raises an unguarded exception must still come back as
    {"detail": ...} with a 500, not a bare/HTML Starlette default error --
    every other error path (HTTPException, 422 validation) already has
    this shape; this is the global exception_handler that gives unhandled
    ones the same one."""
    import main
    from fastapi.testclient import TestClient

    @main.app.get("/api/v1/__test_unhandled_exception__")
    def _boom():
        raise RuntimeError("deliberate test failure")

    # The app also registers a catch-all GET /{full_path:path} (SPA fallback)
    # at import time, which matches first since Starlette tries routes in
    # registration order -- put the new route ahead of it so this actually
    # exercises routing to a real endpoint instead of the SPA 404 path.
    new_route = main.app.router.routes.pop()
    main.app.router.routes.insert(0, new_route)

    # ServerErrorMiddleware sends our handler's response *and then re-raises*
    # the original exception (so real ASGI servers/loggers still see it) --
    # the shared `client` fixture's TestClient re-raises that into the test
    # itself by default. A local client with raise_server_exceptions=False
    # inspects the response actually sent to the caller instead.
    local_client = TestClient(main.app, raise_server_exceptions=False)
    r = local_client.get("/api/v1/__test_unhandled_exception__", headers=auth)
    assert r.status_code == 500
    assert r.json() == {"detail": "Internal server error"}


# ── /stats/findings and /stats/scans: project_id filters at the DB level ────
# (so limit/offset pagination doesn't return a short/empty page when other
# projects' rows are interleaved with this project's in sort order)

def test_findings_and_scans_project_filter_works_with_pagination(client, auth):
    r = client.post("/api/v1/projects", json={"name": "pagination-test-project"}, headers=auth)
    assert r.status_code == 201, r.text
    project_id = r.json()["id"]

    r = client.post(
        f"/api/v1/projects/{project_id}/targets",
        json={"hostname_or_ip": "10.0.0.60", "target_type": "linux_host"},
        headers=auth,
    )
    target_id = r.json()["id"]

    scan = Scan(target_id=target_id, scan_type="network_discovery", module="audit", status="completed",
                raw_output="Nmap scan report for 10.0.0.60\n80/tcp open http\n")
    db = database.SessionLocal()
    try:
        db.add(scan)
        db.commit()
        scan_id = scan.id
        from services.scan_lifecycle import save_parsed_findings
        save_parsed_findings(db, scan, scan.raw_output)
    finally:
        db.close()

    r = client.get(f"/api/v1/scans?project_id={project_id}&limit=50&offset=0", headers=auth)
    assert r.status_code == 200, r.text
    scan_ids = [s["id"] for s in r.json()]
    assert scan_id in scan_ids

    r = client.get(f"/api/v1/findings?project_id={project_id}&limit=50&offset=0", headers=auth)
    assert r.status_code == 200, r.text
    assert len(r.json()) >= 1
    assert all(f["project_id"] == project_id for f in r.json())


# ── Worker process: auto-probe is enqueued, not spawned in-process ──────────

def test_create_target_enqueues_auto_probe_job_when_enabled(client, auth):
    """create_target used to asyncio.create_task(run_auto_probe(...)) directly
    -- a task that dies with the API process. It must now hand off through
    the durable Job queue (database.Job) instead, so worker.py's poller
    picks it up independently of the API process's lifetime."""
    from database import AppSetting, Job

    db = database.SessionLocal()
    try:
        db.merge(AppSetting(key="auto_probe_enabled", value="true"))
        db.commit()
    finally:
        db.close()

    try:
        r = client.post("/api/v1/projects", json={"name": "worker-test-project"}, headers=auth)
        assert r.status_code == 201, r.text
        project_id = r.json()["id"]

        r = client.post(
            f"/api/v1/projects/{project_id}/targets",
            json={"hostname_or_ip": "10.0.0.70", "target_type": "linux_host"},
            headers=auth,
        )
        assert r.status_code == 201, r.text
        target_id = r.json()["id"]

        db = database.SessionLocal()
        try:
            jobs = db.query(Job).filter(Job.job_type == "auto_probe").all()
            matching = [j for j in jobs if json.loads(j.payload_json)["target_id"] == target_id]
            assert len(matching) == 1, "exactly one auto_probe job must be enqueued for this target"
            assert matching[0].status == "pending"
        finally:
            db.close()
    finally:
        db = database.SessionLocal()
        try:
            db.merge(AppSetting(key="auto_probe_enabled", value="false"))
            db.commit()
        finally:
            db.close()


def test_job_runner_picks_up_and_completes_pending_jobs(client, auth):
    """Simulates what worker.py's poller does -- a pending Job transitions
    through running to a terminal state even when the handler itself fails
    (e.g. the real auto-probe tools aren't installed in this test env),
    rather than getting stuck."""
    import asyncio as _asyncio
    from database import Job
    from services.job_runner import poll_pending_jobs

    db = database.SessionLocal()
    try:
        job = Job(job_type="auto_probe", payload_json=json.dumps({
            "target_id": "nonexistent", "target_host": "10.0.0.99", "tools": [], "intensity": "quick",
        }))
        db.add(job)
        db.commit()
        job_id = job.id
    finally:
        db.close()

    _asyncio.run(poll_pending_jobs())

    db = database.SessionLocal()
    try:
        row = db.query(Job).filter(Job.id == job_id).first()
        assert row.status in ("running", "completed", "failed"), "must leave pending immediately"
        assert row.started_at is not None
    finally:
        db.close()


# ── Dry-run mode: report what would execute without touching the target ─────

def test_executor_dry_run_never_spawns_a_subprocess():
    import asyncio as _asyncio
    from services.executor import run_command_streaming, run_argv_streaming

    async def _collect(gen):
        return [msg async for msg in gen]

    msgs = _asyncio.run(_collect(run_command_streaming("touch /tmp/should-not-exist-from-dry-run", dry_run=True)))
    assert msgs[-1] == {"type": "exit", "code": 0}
    assert any("dry-run" in m.get("data", "") for m in msgs if m["type"] == "stdout")

    msgs = _asyncio.run(_collect(run_argv_streaming("echo hello; rm -rf /tmp/should-not-exist", dry_run=True)))
    assert msgs[-1] == {"type": "exit", "code": 0}
    # shlex-split argv is reported literally -- the ";" stays an inert
    # literal argument to `echo`, never a shell separator, dry-run or not.
    dry_run_report = next(m["data"] for m in msgs if m["type"] == "stdout")
    assert "'rm'" in dry_run_report and "'-rf'" in dry_run_report
    # The ";" is glued onto "hello" as one literal argv token (shlex, not a
    # shell, gives it no special meaning) rather than appearing as its own
    # separator token.
    assert "'hello;'" in dry_run_report


def test_ws_execute_dry_run_does_not_change_scan_status(client, auth):
    # Uses its own project rather than the shared `pid` fixture: an earlier
    # test in this file deletes the `pid` project, and this one runs after it.
    r = client.post("/api/v1/projects", json={"name": "dry-run-test-project"}, headers=auth)
    assert r.status_code == 201, r.text
    pid = r.json()["id"]

    r = client.post(
        f"/api/v1/projects/{pid}/targets",
        json={"hostname_or_ip": "10.0.0.32", "target_type": "linux_host"},
        headers=auth,
    )
    target_id = r.json()["id"]
    r = client.post(
        "/api/v1/audit/generate",
        json={
            "project_id": pid,
            "target_id": target_id,
            "scan_categories": [{"category_id": "network_discovery", "config": {}}],
        },
        headers=auth,
    )
    assert r.status_code == 200, r.text
    scan_id = r.json()["scan_id"]

    token = auth["Authorization"].split(" ", 1)[1]
    with client.websocket_connect(f"/ws/execute/{scan_id}?token={token}") as ws:
        ws.send_json({"action": "run", "dry_run": True})
        saw_dry_run_marker = False
        msg = ws.receive_json()
        for _ in range(20):
            if msg.get("type") == "exit":
                assert msg.get("code") == 0
                break
            if "dry-run" in msg.get("data", ""):
                saw_dry_run_marker = True
            msg = ws.receive_json()
        assert saw_dry_run_marker

    db = database.SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        # A dry run must never flip status toward running/completed, or
        # write raw_output as if a real execution happened.
        assert scan.status == "pending"
        assert scan.started_at is None
        assert scan.raw_output is None
    finally:
        db.close()


# ── Per-scan provenance: operator, scope snapshot, script hash ──────────────

def test_ws_execute_records_provenance_on_real_run(client, auth):
    import hashlib

    r = client.post("/api/v1/projects", json={
        "name": "provenance-test-project",
    }, headers=auth)
    assert r.status_code == 201, r.text
    project_id = r.json()["id"]

    scope = {"include": ["10.0.0.0/24"], "exclude": []}
    r = client.put(f"/api/v1/projects/{project_id}/scope", json=scope, headers=auth)
    assert r.status_code == 200, r.text

    r = client.post(
        f"/api/v1/projects/{project_id}/targets",
        json={"hostname_or_ip": "10.0.0.33", "target_type": "linux_host"},
        headers=auth,
    )
    target_id = r.json()["id"]

    r = client.post(
        "/api/v1/audit/generate",
        json={
            "project_id": project_id,
            "target_id": target_id,
            "scan_categories": [{"category_id": "network_discovery", "config": {}}],
        },
        headers=auth,
    )
    assert r.status_code == 200, r.text
    scan_id = r.json()["scan_id"]
    server_script = r.json()["script"]

    token = auth["Authorization"].split(" ", 1)[1]
    with client.websocket_connect(f"/ws/execute/{scan_id}?token={token}") as ws:
        ws.send_json({"action": "run"})
        msg = ws.receive_json()
        for _ in range(20):
            if msg.get("type") == "exit":
                break
            msg = ws.receive_json()

    db = database.SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        prov = json.loads(scan.provenance_json)
        assert prov["operator"] == "smoke"  # the auth fixture's admin username
        assert prov["scope_snapshot"] == scope
        assert prov["category_ids"] == ["network_discovery"]
        assert prov["script_sha256"] == hashlib.sha256(server_script.encode()).hexdigest()
    finally:
        db.close()


# ── Evidence chain-of-custody: output_hash, screenshot sha256, audit chain ──

def test_save_parsed_findings_records_output_hash(client, auth):
    import hashlib

    r = client.post("/api/v1/projects", json={"name": "coc-test-project"}, headers=auth)
    project_id = r.json()["id"]
    r = client.post(
        f"/api/v1/projects/{project_id}/targets",
        json={"hostname_or_ip": "10.0.0.61", "target_type": "linux_host"},
        headers=auth,
    )
    target_id = r.json()["id"]

    raw = "Nmap scan report for 10.0.0.61\n22/tcp open ssh\n"
    scan = Scan(target_id=target_id, scan_type="network_discovery", module="audit", status="completed", raw_output=raw)
    db = database.SessionLocal()
    try:
        db.add(scan)
        db.commit()
        from services.scan_lifecycle import save_parsed_findings
        save_parsed_findings(db, scan, raw)
        assert scan.output_hash == hashlib.sha256(raw.encode()).hexdigest()
    finally:
        db.close()


def test_screenshot_index_results_computes_sha256(tmp_path):
    from services.screenshot import index_results, _file_sha256

    img = tmp_path / "shot.png"
    img.write_bytes(b"not-a-real-png-but-bytes-are-bytes")

    job = {
        "project_id": "p1",
        "target_id": None,
        "urls": ["http://example.com"],
        "outdir": str(tmp_path),
    }
    rows = index_results(job)
    assert len(rows) == 1
    assert rows[0]["sha256"] == _file_sha256(str(img))


def test_audit_log_hash_chain_is_internally_consistent(client, auth):
    import hashlib
    from database import AuditLog

    # Any mutating request appends a row.
    client.post("/api/v1/projects", json={"name": "audit-chain-test-1"}, headers=auth)
    client.post("/api/v1/projects", json={"name": "audit-chain-test-2"}, headers=auth)

    db = database.SessionLocal()
    try:
        rows = db.query(AuditLog).order_by(AuditLog.created_at, AuditLog.id).all()
        assert len(rows) >= 2
        for i, row in enumerate(rows):
            expected_prev = "0" * 64 if i == 0 else rows[i - 1].row_hash
            assert row.prev_hash == expected_prev, "chain must link to the immediately preceding row's hash"
            recomputed = hashlib.sha256(
                f"{row.prev_hash}|{row.action}|{row.user_id}|{row.resource_type}|"
                f"{row.resource_id}|{row.ip_address}|{row.created_at.isoformat()}".encode()
            ).hexdigest()
            assert row.row_hash == recomputed, "row_hash must be reproducible from its own fields + prev_hash"
    finally:
        db.close()
