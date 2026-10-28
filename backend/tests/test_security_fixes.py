"""Regression tests for the security/correctness fix pass (security-correctness-fixes branch).

Each test targets one specific fix called out in the audit/review docs and
the approved plan. Run alongside the smoke suite:  cd backend && pytest tests -q
"""

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
        from services.output_parser import save_parsed_findings
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
        from services.output_parser import save_parsed_findings
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
        from services.output_parser import save_parsed_findings
        all_current, new_count = save_parsed_findings(db, scan, raw)
        assert len(all_current) == 1, "must not duplicate the finding"
        assert new_count == 0, "must not count the existing finding as new"
        assert all_current[0].id == fid
        assert all_current[0].status == "accepted", "status must survive a rescan"
        assert all_current[0].tags == "reviewed", "tags must survive a rescan"
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
