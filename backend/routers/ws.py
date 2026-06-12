import logging
import os
import secrets
import tempfile
import stat as stat_mod
import json
import asyncio
import uuid
from datetime import datetime

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from database import SessionLocal, Scan, Credential, Notification, Target, Project
from services.executor import run_command_streaming
from services.ssh_executor import run_script_over_ssh, REMOTE_CATEGORIES
from services.scope_service import check_scope

log = logging.getLogger(__name__)
router = APIRouter(tags=["websocket"])

# ── Operator command audit log ────────────────────────────────────────────────
_CMD_LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'operator_commands.log')
os.makedirs(os.path.dirname(_CMD_LOG_PATH), exist_ok=True)
_cmd_log = logging.getLogger('seraph.operator_commands')
if not _cmd_log.handlers:
    _fh = logging.FileHandler(_CMD_LOG_PATH)
    _fh.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
    _cmd_log.addHandler(_fh)
    _cmd_log.setLevel(logging.DEBUG)
    _cmd_log.propagate = False


def _log_command(scan_id: str, raw_script: str) -> None:
    has_sudo = raw_script.lstrip().startswith('sudo ')
    _cmd_log.info(
        '[scan=%s] sudo=%s | %s',
        scan_id,
        has_sudo,
        raw_script[:300].replace('\n', ' '),
    )

# ── Global event broadcast ────────────────────────────────────────────────────

_event_clients: set[asyncio.Queue] = set()


async def broadcast_event(event: dict) -> None:
    """Push an event to all connected /ws/events clients."""
    dead = set()
    for q in _event_clients:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            dead.add(q)
    _event_clients.difference_update(dead)


@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """Lightweight event stream — clients reconnect on disconnect."""
    await websocket.accept()
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    _event_clients.add(q)
    try:
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=25.0)
                await websocket.send_json(event)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        _event_clients.discard(q)


def _save_and_parse(db, scan, full_output: list[str], exit_code: int) -> None:
    """Persist scan output and auto-generate findings from parsed results."""
    from services.output_parser import auto_parse_scan_output
    from database import Finding

    scan.status = "completed" if exit_code == 0 else "failed"
    scan.completed_at = datetime.utcnow()
    scan.raw_output = "".join(full_output)
    db.commit()

    if scan.status == "completed" and scan.raw_output:
        try:
            parsed = auto_parse_scan_output(scan.scan_type, scan.raw_output)
            if parsed:
                db.query(Finding).filter(Finding.scan_id == scan.id).delete()
                for pf in parsed:
                    db.add(Finding(
                        id=str(uuid.uuid4()),
                        scan_id=scan.id,
                        title=pf.title,
                        description=pf.description,
                        severity=pf.severity,
                        control_id=pf.control_id,
                        framework=pf.framework,
                        remediation=pf.remediation,
                        evidence=pf.evidence,
                        status="open",
                    ))
                # Notify user
                highs = sum(1 for p in parsed if p.severity in ("critical", "high"))
                notif_type = "critical" if highs > 0 else "info"
                db.add(Notification(
                    title=f"Scan complete — {len(parsed)} finding(s)",
                    body=f"{scan.scan_type}: {len(parsed)} finding(s) parsed" + (f", {highs} critical/high" if highs else ""),
                    type=notif_type,
                    scan_id=scan.id,
                ))
                db.commit()
        except Exception:
            log.exception("Failed to parse findings for scan %s", scan.id)


@router.websocket("/ws/execute/{scan_id}")
async def websocket_execute(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    db = SessionLocal()

    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            await websocket.send_json({"type": "error", "data": "Scan not found"})
            await websocket.close()
            return

        # ── Scope enforcement ────────────────────────────────────────────────
        if scan.target_id:
            _tgt = db.query(Target).filter(Target.id == scan.target_id).first()
            if _tgt and _tgt.project_id:
                _proj = db.query(Project).filter(Project.id == _tgt.project_id).first()
                if _proj:
                    in_scope, reason = check_scope(_tgt.hostname_or_ip, _proj.scope_json)
                    if not in_scope:
                        await websocket.send_json({
                            "type": "error",
                            "data": f"[SCOPE BLOCK] {_tgt.hostname_or_ip} is out of scope: {reason}",
                        })
                        scan.status = "failed"
                        scan.raw_output = f"Scope block: {reason}"
                        db.commit()
                        await websocket.close()
                        return

        # Wait for the client to send the script to execute
        data = await websocket.receive_json()
        if data.get("action") != "run":
            await websocket.send_json({"type": "error", "data": "Expected action: run"})
            await websocket.close()
            return

        script_content = data.get("script", "")
        if not script_content:
            await websocket.send_json({"type": "error", "data": "No script provided"})
            await websocket.close()
            return

        _log_command(scan_id, script_content)

        # Determine whether this scan uses SSH remote execution
        config = {}
        try:
            config = json.loads(scan.config_json or "{}")
        except Exception:
            pass

        credential_id = config.get("credential_id")
        scan_categories = [c.get("category_id", "") for c in config.get("categories", [])]
        needs_ssh = credential_id and any(c in REMOTE_CATEGORIES for c in scan_categories)

        scan.status = "running"
        scan.started_at = datetime.utcnow()
        db.commit()

        full_output = []
        client_connected = True

        if needs_ssh:
            # Look up the credential and the target host
            cred = db.query(Credential).filter(Credential.id == credential_id).first()
            if not cred or cred.cred_type != "key":
                await websocket.send_json({"type": "error", "data": "SSH credential not found or wrong type"})
                scan.status = "failed"
                db.commit()
                return

            target = db.query(Target).filter(Target.id == scan.target_id).first()
            if not target:
                await websocket.send_json({"type": "error", "data": "Target not found"})
                scan.status = "failed"
                db.commit()
                return

            ssh_user = cred.username or "root"
            ssh_host = target.hostname_or_ip
            await websocket.send_json({
                "type": "stdout",
                "data": f"[Seraph] Connecting to {ssh_user}@{ssh_host} via SSH...\r\n",
                "code": None,
            })

            async for message in run_script_over_ssh(ssh_host, ssh_user, cred.secret, script_content):
                if message["type"] in ("stdout", "stderr"):
                    full_output.append(message["data"])
                elif message["type"] == "exit":
                    _save_and_parse(db, scan, full_output, message["code"])
                if client_connected:
                    try:
                        await websocket.send_json(message)
                    except (WebSocketDisconnect, Exception):
                        client_connected = False
        else:
            # Local execution (original path)
            import stat
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False, prefix='seraph_') as f:
                f.write(script_content)
                tmpfile = f.name

            os.chmod(tmpfile, stat.S_IRWXU)

            try:
                async for message in run_command_streaming(f"bash {tmpfile}"):
                    if message["type"] in ("stdout", "stderr"):
                        full_output.append(message["data"])
                    elif message["type"] == "exit":
                        _save_and_parse(db, scan, full_output, message["code"])
                    if client_connected:
                        try:
                            await websocket.send_json(message)
                        except (WebSocketDisconnect, Exception):
                            client_connected = False
            finally:
                os.unlink(tmpfile)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "data": str(e)})
        except Exception:
            pass
    finally:
        db.close()


@router.websocket("/ws/hermes/{scan_id}")
async def websocket_hermes(websocket: WebSocket, scan_id: str):
    """Run a prepared Hermes Agent engagement and stream its transcript."""
    await websocket.accept()
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            await websocket.send_json({"type": "error", "data": "Run not found"})
            await websocket.close()
            return

        config = json.loads(scan.config_json or "{}")
        command = config.get("command", "")
        if not command:
            await websocket.send_json({"type": "error", "data": "No command in run record"})
            await websocket.close()
            return

        # Wait for the client's run signal (mirrors /ws/execute).
        data = await websocket.receive_json()
        if data.get("action") != "run":
            await websocket.send_json({"type": "error", "data": "Expected action: run"})
            await websocket.close()
            return

        scan.status = "running"
        scan.started_at = datetime.utcnow()
        db.commit()

        full_output: list[str] = []
        client_connected = True
        async for message in run_command_streaming(command):
            if message["type"] in ("stdout", "stderr"):
                full_output.append(message["data"])
            elif message["type"] == "exit":
                scan.raw_output = "".join(full_output)[:500000]
                scan.status = "completed" if message["code"] == 0 else "failed"
                scan.completed_at = datetime.utcnow()
                db.commit()
                await broadcast_event({"type": "scan_update", "scan_id": scan_id,
                                       "status": scan.status, "progress": 100})
            if client_connected:
                try:
                    await websocket.send_json(message)
                except (WebSocketDisconnect, Exception):
                    client_connected = False

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "data": str(e)})
        except Exception:
            pass
    finally:
        db.close()


@router.websocket("/ws/pentest/{scan_id}")
async def websocket_pentest(websocket: WebSocket, scan_id: str):
    """Execute a pentest tool command and stream output."""
    await websocket.accept()
    db = SessionLocal()

    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            await websocket.send_json({"type": "error", "data": "Scan not found"})
            await websocket.close()
            return

        config = json.loads(scan.config_json or "{}")
        command = config.get("command", "")

        if not command:
            await websocket.send_json({"type": "error", "data": "No command in scan record"})
            await websocket.close()
            return

        # Update scan status
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        db.commit()

        full_output = []
        client_connected = True
        async for message in run_command_streaming(command):
            # Collect output regardless of client state
            if message["type"] in ("stdout", "stderr"):
                full_output.append(message["data"])
            elif message["type"] == "exit":
                _save_and_parse(db, scan, full_output, message["code"])
            # Forward to client if still connected — don't abort if they left
            if client_connected:
                try:
                    await websocket.send_json(message)
                except (WebSocketDisconnect, Exception):
                    client_connected = False

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "data": str(e)})
        except Exception:
            pass
    finally:
        db.close()


@router.websocket("/ws/cracking/{job_id}")
async def websocket_cracking(websocket: WebSocket, job_id: str):
    """Stream a password cracking job, parse results, update Credential Vault."""
    await websocket.accept()
    db = SessionLocal()
    hash_file: str | None = None
    out_file: str | None = None

    try:
        from database import CrackingJob, CrackingServer, Credential
        job = db.query(CrackingJob).filter(CrackingJob.id == job_id).first()
        if not job:
            await websocket.send_json({"type": "error", "data": "Job not found"})
            await websocket.close()
            return

        config = json.loads(job.config_json or "{}")
        tool = config.get("tool", "hashcat")
        hashes = config.get("hashes", [])
        command_tmpl = config.get("command", "")
        wordlist = config.get("wordlist", "")
        credential_ids = config.get("credential_ids", [])
        server_id = config.get("server_id", "")
        remote_wordlist = config.get("remote_wordlist", "") or "/usr/share/wordlists/rockyou.txt"
        hash_type = config.get("hash_type", "0")

        if not hashes or not command_tmpl:
            await websocket.send_json({"type": "error", "data": "Missing hashes or command"})
            await websocket.close()
            return

        # ── Remote cracking branch (SSH) ─────────────────────────────────────
        if server_id:
            srv = db.query(CrackingServer).filter(CrackingServer.id == server_id).first()
            if not srv:
                await websocket.send_json({"type": "error", "data": "Cracking server not found"})
                await websocket.close()
                return

            key_pem = ""
            if srv.key_credential_id:
                key_cred = db.query(Credential).filter(Credential.id == srv.key_credential_id).first()
                if key_cred:
                    key_pem = key_cred.secret or ""

            workdir = f"{srv.remote_workdir}/{job_id[:8]}"
            hash_lines = "\n".join(hashes)

            if tool == "hashcat":
                crack_cmd = (
                    f"hashcat -m {hash_type} -a 0 $WORKDIR/hashes.txt {remote_wordlist} "
                    f"--outfile $WORKDIR/out.txt --outfile-format 2 --status --status-timer 10 --force 2>&1 || true"
                )
                parse_block = "cat $WORKDIR/out.txt 2>/dev/null || true"
            else:
                crack_cmd = (
                    f"john --wordlist={remote_wordlist} $WORKDIR/hashes.txt 2>&1 || true && "
                    f"john --show $WORKDIR/hashes.txt 2>/dev/null || true"
                )
                parse_block = "john --show $WORKDIR/hashes.txt 2>/dev/null || true"

            remote_script = f"""#!/bin/bash
set -e
WORKDIR={workdir}
mkdir -p $WORKDIR
cat > $WORKDIR/hashes.txt << 'HASHEOF'
{hash_lines}
HASHEOF
{crack_cmd}
echo '=== SERAPH_CRACKED_RESULTS ==='
{parse_block}
rm -rf $WORKDIR
"""
            job.status = "running"
            job.started_at = datetime.utcnow()
            db.commit()

            full_output: list[str] = []
            exit_code = 0
            async for message in run_script_over_ssh(srv.host, srv.ssh_user, key_pem, remote_script, port=srv.port):
                if message["type"] == "exit":
                    exit_code = message.get("code", 0)
                    await websocket.send_json(message)
                else:
                    await websocket.send_json(message)
                    full_output.append(message.get("data", ""))

            raw = "".join(full_output)
            job.status = "completed"
            job.completed_at = datetime.utcnow()
            job.raw_output = raw
            db.commit()

            # Parse cracked pairs from delimiter-separated section
            cracked_pairs: list[dict] = []
            if "=== SERAPH_CRACKED_RESULTS ===" in raw:
                results_section = raw.split("=== SERAPH_CRACKED_RESULTS ===", 1)[1]
                for line in results_section.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    if tool == "hashcat" and ":" in line:
                        h, _, plain = line.partition(":")
                        cracked_pairs.append({"hash": h, "plain": plain})
                    elif tool == "john" and ":" in line:
                        parts = line.split(":")
                        if len(parts) >= 2 and not parts[0].endswith(" password"):
                            # john --show format: hash:plain:...
                            cracked_pairs.append({"hash": parts[0], "plain": parts[1]})

            vault_updated = 0
            if cracked_pairs and credential_ids:
                creds = db.query(Credential).filter(Credential.id.in_(credential_ids)).all()
                hash_to_plain = {p["hash"]: p["plain"] for p in cracked_pairs}
                for cred in creds:
                    plain = hash_to_plain.get(cred.secret)
                    if plain:
                        cred.secret = plain
                        cred.cred_type = "password"
                        vault_updated += 1
                db.commit()

            await websocket.send_json({
                "type": "results",
                "cracked": len(cracked_pairs),
                "pairs": cracked_pairs[:50],
                "vault_updated": vault_updated,
            })
            return

        # Write hashes to temp file.
        # For john: label each line with its index ("0:hash\n1:hash\n") so that
        # `john --show` returns "0:plaintext:..." instead of "?:plaintext:..."
        # allowing us to map each plaintext back to the original hash value.
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="seraph_hashes_") as f:
            if tool == "john":
                f.write("\n".join(f"{i}:{h}" for i, h in enumerate(hashes)) + "\n")
            else:
                f.write("\n".join(hashes) + "\n")
            hash_file = f.name

        out_file = f"/tmp/seraph_cracked_{job_id[:8]}.txt"

        # Substitute placeholders
        command = (
            command_tmpl
            .replace("HASH_FILE", hash_file)
            .replace("OUT_FILE", out_file)
            .replace("WORD_FILE", wordlist)
        )

        job.status = "running"
        job.started_at = datetime.utcnow()
        db.commit()

        full_output: list[str] = []
        async for message in run_command_streaming(command):
            await websocket.send_json(message)
            if message["type"] in ("stdout", "stderr"):
                full_output.append(message["data"])
            elif message["type"] == "exit":
                raw = "".join(full_output)
                # hashcat exits 1 on "exhausted" — still treat as completed
                job.status = "completed"
                job.completed_at = datetime.utcnow()
                job.raw_output = raw
                db.commit()

                # ── Parse cracked pairs ──────────────────────────────────────
                cracked_pairs: list[dict] = []

                if tool == "hashcat" and out_file and os.path.exists(out_file):
                    with open(out_file) as f:
                        for line in f:
                            line = line.strip()
                            if ":" in line:
                                h, _, plain = line.partition(":")
                                cracked_pairs.append({"hash": h, "plain": plain})

                elif tool == "john":
                    import subprocess
                    try:
                        result = subprocess.run(
                            ["john", "--show", hash_file],
                            capture_output=True, text=True, timeout=15,
                        )
                        for line in result.stdout.splitlines():
                            # Format: "index:plaintext:..." or summary "N password hashes cracked"
                            if ":" not in line:
                                continue
                            parts = line.split(":")
                            if len(parts) < 2:
                                continue
                            label = parts[0]
                            plain = parts[1]
                            # Skip john's summary line
                            if not plain or label.endswith(" password"):
                                continue
                            # Map label (index) back to original hash
                            try:
                                orig_hash = hashes[int(label)]
                            except (ValueError, IndexError):
                                orig_hash = label  # fallback: use label as-is
                            cracked_pairs.append({"hash": orig_hash, "plain": plain})
                    except Exception:
                        pass

                # ── Update matched Credentials in vault ──────────────────────
                vault_updated = 0
                if cracked_pairs and credential_ids:
                    creds = db.query(Credential).filter(Credential.id.in_(credential_ids)).all()
                    hash_to_plain = {p["hash"]: p["plain"] for p in cracked_pairs}
                    for cred in creds:
                        plain = hash_to_plain.get(cred.secret)
                        if plain:
                            cred.secret = plain
                            cred.cred_type = "password"
                            vault_updated += 1
                    db.commit()

                await websocket.send_json({
                    "type": "results",
                    "cracked": len(cracked_pairs),
                    "pairs": cracked_pairs[:50],
                    "vault_updated": vault_updated,
                })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "data": str(e)})
        except Exception:
            pass
    finally:
        db.close()
        for path in (hash_file, out_file):
            if path and os.path.exists(path):
                try:
                    os.unlink(path)
                except Exception:
                    pass


@router.websocket("/ws/wordlists/install/{bundle_id}")
async def websocket_wordlist_install(websocket: WebSocket, bundle_id: str):
    """Stream wordlist bundle installation (apt-get + gunzip)."""
    await websocket.accept()
    try:
        from routers.cracking import WORDLIST_BUNDLES
        bundle = next((b for b in WORDLIST_BUNDLES if b["id"] == bundle_id), None)
        if not bundle:
            await websocket.send_json({"type": "error", "data": f"Unknown bundle: {bundle_id}"})
            await websocket.close()
            return

        for cmd in bundle["commands"]:
            await websocket.send_json({"type": "stdout", "data": f"$ {cmd}\r\n"})
            async for msg in run_command_streaming(cmd):
                await websocket.send_json(msg)

        installed = os.path.exists(bundle["dest"])
        await websocket.send_json({
            "type": "done",
            "installed": installed,
            "dest": bundle["dest"] if installed else "",
        })
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "data": str(e)})
        except Exception:
            pass


@router.websocket("/ws/osint/{scan_id}")
async def websocket_osint(websocket: WebSocket, scan_id: str):
    """Execute an OSINT tool, stream output, then parse and save results."""
    await websocket.accept()
    db = SessionLocal()

    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            await websocket.send_json({"type": "error", "data": "Scan not found"})
            await websocket.close()
            return

        config = json.loads(scan.config_json or "{}")
        command = config.get("command", "")
        domain = config.get("domain", "")
        project_id = config.get("project_id", "")

        if not command:
            await websocket.send_json({"type": "error", "data": "No command in scan record"})
            await websocket.close()
            return

        scan.status = "running"
        scan.started_at = datetime.utcnow()
        db.commit()

        full_output = []
        client_connected = True
        async for message in run_command_streaming(command):
            if message["type"] in ("stdout", "stderr"):
                full_output.append(message["data"])
            elif message["type"] == "exit":
                raw = "".join(full_output)
                scan.status = "completed" if message["code"] == 0 else "failed"
                scan.completed_at = datetime.utcnow()
                scan.raw_output = raw
                db.commit()

                if domain:
                    from services.osint_parser import parse_osint_output
                    from database import Finding  # Target is already module-level

                    results = parse_osint_output(raw, domain)

                    for email in results.emails:
                        db.add(Finding(
                            scan_id=scan_id, severity="info",
                            title=f"Email: {email}",
                            description="Email address discovered via OSINT.",
                            framework="osint",
                        ))
                    for subdomain in results.subdomains:
                        db.add(Finding(
                            scan_id=scan_id, severity="info",
                            title=f"Subdomain: {subdomain}",
                            description="Subdomain discovered via OSINT.",
                            framework="osint",
                        ))
                    for ip in results.ips:
                        db.add(Finding(
                            scan_id=scan_id, severity="info",
                            title=f"IP Address: {ip}",
                            description="IP address discovered via OSINT.",
                            framework="osint",
                        ))
                    db.commit()

                    # Auto-create targets for newly discovered subdomains
                    new_targets = 0
                    if project_id:
                        existing = {
                            t.hostname_or_ip
                            for t in db.query(Target).filter(Target.project_id == project_id).all()
                        }
                        for subdomain in results.subdomains:
                            if subdomain not in existing:
                                db.add(Target(
                                    project_id=project_id,
                                    hostname_or_ip=subdomain,
                                    target_type="web_app",
                                ))
                                new_targets += 1
                        db.commit()

                    if client_connected:
                        try:
                            await websocket.send_json({
                                "type": "results",
                                "emails": len(results.emails),
                                "subdomains": len(results.subdomains),
                                "ips": len(results.ips),
                                "new_targets": new_targets if project_id else 0,
                            })
                        except (WebSocketDisconnect, Exception):
                            client_connected = False

            if client_connected:
                try:
                    await websocket.send_json(message)
                except (WebSocketDisconnect, Exception):
                    client_connected = False

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "data": str(e)})
        except Exception:
            pass
    finally:
        db.close()


@router.websocket("/ws/screenshots/{job_id}")
async def websocket_screenshots(websocket: WebSocket, job_id: str):
    """Run a gowitness capture, stream output, then index produced images."""
    from services.screenshot import get_job, index_results, finish_job
    from database import Screenshot

    await websocket.accept()
    db = SessionLocal()
    try:
        job = get_job(job_id)
        if not job:
            await websocket.send_json({"type": "error", "data": "Capture job not found or expired"})
            await websocket.close()
            return

        client_connected = True
        async for message in run_command_streaming(job["command"]):
            if message["type"] == "exit":
                rows = index_results(job)
                for r in rows:
                    db.add(Screenshot(**r))
                db.commit()
                finish_job(job_id)
                if client_connected:
                    try:
                        await websocket.send_json({"type": "results", "captured": len(rows)})
                    except Exception:
                        client_connected = False

            if client_connected:
                try:
                    await websocket.send_json(message)
                except (WebSocketDisconnect, Exception):
                    client_connected = False

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "data": str(e)})
        except Exception:
            pass
    finally:
        db.close()


@router.websocket("/ws/httpfuzz/{run_id}")
async def websocket_httpfuzz(websocket: WebSocket, run_id: str):
    """Stream HTTP fuzz results, one message per payload, then a summary."""
    from services.http_workbench import get_fuzz_job, run_fuzz, finish_fuzz_job

    await websocket.accept()
    try:
        job = get_fuzz_job(run_id)
        if not job:
            await websocket.send_json({"type": "error", "data": "Fuzz job not found or expired"})
            await websocket.close()
            return

        await websocket.send_json({"type": "start", "total": len(job["payloads"])})
        sent = 0
        async for result in run_fuzz(job):
            sent += 1
            await websocket.send_json({"type": "result", **result})
        await websocket.send_json({"type": "exit", "code": 0, "completed": sent})
        finish_fuzz_job(run_id)

    except WebSocketDisconnect:
        finish_fuzz_job(run_id)
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "data": str(e)})
        except Exception:
            pass


@router.websocket("/ws/sherlock/{job_id}")
async def websocket_sherlock(websocket: WebSocket, job_id: str):
    """Run a sherlock username search and stream output with parsed profile results."""
    await websocket.accept()
    db = SessionLocal()
    try:
        from database import SherlockJob
        import re as _re

        job = db.query(SherlockJob).filter(SherlockJob.id == job_id).first()
        if not job:
            await websocket.send_json({"type": "error", "data": "Job not found"})
            await websocket.close()
            return

        command = job.command or ""
        username = job.username

        if not command:
            await websocket.send_json({"type": "error", "data": "No command in job record"})
            await websocket.close()
            return

        job.status = "running"
        job.started_at = datetime.utcnow()
        db.commit()

        full_output: list[str] = []
        client_connected = True

        async for message in run_command_streaming(command):
            if message["type"] in ("stdout", "stderr"):
                full_output.append(message["data"])
            elif message["type"] == "exit":
                raw = "".join(full_output)
                job.status = "completed" if message["code"] == 0 else "failed"
                job.completed_at = datetime.utcnow()
                job.raw_output = raw

                profiles = []
                for line in raw.splitlines():
                    m = _re.match(r'^\[\+\] (.+?):\s+(https?://\S+)', line)
                    if m:
                        profiles.append({"site": m.group(1), "url": m.group(2)})

                job.results_json = json.dumps(profiles)
                db.commit()

                if client_connected:
                    try:
                        await websocket.send_json({
                            "type": "results",
                            "username": username,
                            "profiles": profiles,
                            "total_found": len(profiles),
                        })
                    except (WebSocketDisconnect, Exception):
                        client_connected = False

            if client_connected:
                try:
                    await websocket.send_json(message)
                except (WebSocketDisconnect, Exception):
                    client_connected = False

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "data": str(e)})
        except Exception:
            pass
    finally:
        db.close()


@router.websocket("/ws/c2/{seraph_session_id}")
async def websocket_c2(websocket: WebSocket, seraph_session_id: str):
    """Interactive WebSocket terminal for a C2 session."""
    await websocket.accept()
    db = SessionLocal()
    try:
        from database import C2Session
        import services.msf_client as msf_svc
        session = db.query(C2Session).filter(C2Session.id == seraph_session_id).first()
        if not session:
            await websocket.send_json({"type": "error", "data": "Session not found"})
            await websocket.close()
            return
        if not session.msf_session_id:
            await websocket.send_json({"type": "error", "data": "No MSF session linked"})
            await websocket.close()
            return

        await websocket.send_json({"type": "stdout", "data": f"\r\n\x1b[36m[*] Connected to session {session.msf_session_id} ({session.remote_host}) via {session.via_exploit or 'unknown'}\x1b[0m\r\n"})
        await websocket.send_json({"type": "stdout", "data": f"\x1b[90m    Type: {session.session_type} | Platform: {session.platform} | Arch: {session.arch}\x1b[0m\r\n\r\n"})

        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_json(), timeout=60.0)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
                continue

            if data.get("action") == "exec":
                command = (data.get("command") or "").strip()
                if not command:
                    continue
                await websocket.send_json({"type": "stdout", "data": f"\x1b[32mseraph@c2>\x1b[0m {command}\r\n"})

                # Run in thread to avoid blocking
                loop = asyncio.get_event_loop()
                output = await loop.run_in_executor(
                    None,
                    lambda: msf_svc.session_run_command(session.msf_session_id, command, timeout=30)
                )

                if output:
                    await websocket.send_json({"type": "stdout", "data": output + "\r\n"})

                # Log the task
                from database import C2Task
                from datetime import datetime as dt
                task = C2Task(
                    id=str(uuid.uuid4()),
                    session_id=seraph_session_id,
                    command=command,
                    output=output or "",
                    status="done",
                    executed_at=dt.utcnow(),
                    completed_at=dt.utcnow(),
                )
                db.add(task)
                session.last_seen = dt.utcnow()
                db.commit()

            elif data.get("action") == "close":
                break

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "data": str(e)})
        except Exception:
            pass
    finally:
        db.close()


@router.websocket("/ws/playbooks/{run_id}")
async def websocket_playbook_run(websocket: WebSocket, run_id: str, use_ai: bool = False):
    """Stream playbook execution output. Receives 'continue' messages in step-through mode.

    Query params:
        use_ai: If true, call the configured LLM after each step and push step_ai messages.
    """
    await websocket.accept()

    from services.playbook_runner import execute_playbook_run, signal_continue, cleanup_run

    async def send(msg: dict):
        try:
            await websocket.send_json(msg)
        except Exception:
            pass

    task = asyncio.create_task(execute_playbook_run(run_id, send, use_ai=use_ai))

    try:
        while not task.done():
            try:
                data = await asyncio.wait_for(websocket.receive_json(), timeout=5.0)
                if data.get("type") == "continue":
                    signal_continue(run_id)
            except asyncio.TimeoutError:
                continue
            except WebSocketDisconnect:
                break
            except Exception:
                break
    finally:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
        cleanup_run(run_id)


# Per-tool package names by package manager.
# Keys: apt | dnf | pacman | brew | apk | zypper | go (go install path)
_TOOL_PKGS: dict[str, dict[str, str]] = {
    "nmap":         {"apt": "nmap",             "dnf": "nmap",           "pacman": "nmap",        "brew": "nmap",          "apk": "nmap",       "zypper": "nmap"},
    "nikto":        {"apt": "nikto",            "dnf": "nikto",          "pacman": "nikto",       "brew": "nikto",         "apk": "nikto",      "zypper": "nikto"},
    "testssl":      {"apt": "testssl.sh",       "pacman": "testssl.sh",  "brew": "testssl"},
    "lynis":        {"apt": "lynis",            "dnf": "lynis",          "pacman": "lynis",       "brew": "lynis",         "zypper": "lynis"},
    "oscap":        {"apt": "libopenscap8 openscap-scanner", "dnf": "openscap-scanner", "zypper": "openscap"},
    "masscan":      {"apt": "masscan",          "dnf": "masscan",        "pacman": "masscan",     "brew": "masscan"},
    "gobuster":     {"apt": "gobuster",         "brew": "gobuster",      "go": "github.com/OJ/gobuster/v3@latest"},
    "sqlmap":       {"apt": "sqlmap",           "dnf": "sqlmap",         "pacman": "sqlmap",      "brew": "sqlmap"},
    "hydra":        {"apt": "hydra",            "dnf": "hydra",          "pacman": "hydra",       "brew": "hydra"},
    "whois":        {"apt": "whois",            "dnf": "whois",          "pacman": "whois",       "brew": "whois"},
    "dig":          {"apt": "dnsutils",         "dnf": "bind-utils",     "pacman": "bind",        "brew": "bind",          "apk": "bind-tools", "zypper": "bind-utils"},
    "theHarvester": {},
    "subfinder":    {"brew": "subfinder",       "go": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    "enum4linux":   {},
    "smbclient":    {"apt": "smbclient",        "dnf": "samba-client",   "pacman": "smbclient",   "brew": "samba"},
    "netdiscover":  {"apt": "netdiscover",      "dnf": "netdiscover"},
    "wfuzz":        {"apt": "wfuzz",            "brew": "wfuzz"},
    "xsser":        {"apt": "xsser"},
    "weevely":      {"apt": "weevely"},
    "searchsploit": {},
    "aws":          {"brew": "awscli",           "pip": "awscli"},
    "hashcat":      {"apt": "hashcat",          "dnf": "hashcat",        "pacman": "hashcat",     "brew": "hashcat"},
    "john":         {"apt": "john",             "dnf": "john",           "pacman": "john",        "brew": "john"},
    "ffuf":              {"brew": "ffuf",            "go": "github.com/ffuf/ffuf/v2@latest"},
    "rustscan":          {"snap": "rustscan"},
    "nuclei":            {"brew": "nuclei",          "go": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
    "feroxbuster":       {"brew": "feroxbuster"},
    "kerbrute":          {"go": "github.com/ropnop/kerbrute@latest"},
    "nxc":               {"pip": "netexec"},
    "impacket-GetUserSPNs":  {"pip": "impacket"},
    "impacket-GetNPUsers":   {"pip": "impacket"},
    "impacket-secretsdump":  {"pip": "impacket"},
    "impacket-psexec":       {"pip": "impacket"},
    "impacket-wmiexec":      {"pip": "impacket"},
    "responder":             {},
}


def _detect_pkg_manager() -> str:
    import shutil as _shutil
    try:
        with open("/etc/os-release") as f:
            content = f.read()
        import re as _re
        id_match = _re.search(r'^ID="?([^"\n]+)"?', content, _re.MULTILINE)
        like_match = _re.search(r'^ID_LIKE="?([^"\n]+)"?', content, _re.MULTILINE)
        distro_id = (id_match.group(1) if id_match else "").lower()
        id_like = (like_match.group(1) if like_match else "").lower()
        if distro_id in ("ubuntu", "debian", "kali", "parrot", "raspbian", "linuxmint") or "debian" in id_like:
            return "apt"
        if distro_id in ("fedora", "rhel", "centos", "almalinux", "rocky") or "fedora" in id_like or "rhel" in id_like:
            return "dnf" if _shutil.which("dnf") else "yum"
        if distro_id in ("arch", "manjaro", "endeavouros") or "arch" in id_like:
            return "pacman"
        if distro_id == "alpine":
            return "apk"
        if "suse" in distro_id or "suse" in id_like:
            return "zypper"
    except FileNotFoundError:
        pass
    import platform as _platform
    if _platform.system() == "Darwin":
        return "brew"
    for mgr in ("apt", "dnf", "yum", "pacman", "apk", "zypper"):
        if _shutil.which(mgr):
            return mgr
    return "apt"


def _get_install_command(tool_name: str) -> str | None:
    import shutil as _shutil
    from services.tool_registry import _install_hint

    # Use the centralized hint first; skip bare URLs (not executable)
    hint = _install_hint(tool_name)
    if hint and not hint.startswith("http"):
        return hint

    # Fallback: _TOOL_PKGS covers extra tools not in tool_registry
    pkgs = _TOOL_PKGS.get(tool_name)
    if not pkgs:
        return None
    mgr = _detect_pkg_manager()
    pkg = pkgs.get(mgr)
    if pkg:
        if mgr == "apt":
            return f"sudo apt-get install -y {pkg}"
        if mgr in ("dnf", "yum"):
            return f"sudo {mgr} install -y {pkg}"
        if mgr == "pacman":
            return f"sudo pacman -S --noconfirm {pkg}"
        if mgr == "apk":
            return f"sudo apk add {pkg}"
        if mgr == "zypper":
            return f"sudo zypper install -y {pkg}"
        if mgr == "brew":
            return f"brew install {pkg}"
    go_path = pkgs.get("go")
    if go_path:
        return f"go install {go_path}"
    snap_pkg = pkgs.get("snap")
    if snap_pkg and _shutil.which("snap"):
        return f"sudo snap install {snap_pkg}"
    cargo_pkg = pkgs.get("cargo")
    if cargo_pkg and _shutil.which("cargo"):
        return f"cargo install {cargo_pkg}"
    pip_pkg = pkgs.get("pip")
    if pip_pkg:
        pip_bin = _shutil.which("pip3") or _shutil.which("pip") or "pip3"
        return f"{pip_bin} install {pip_pkg}"
    return None


@router.websocket("/ws/install/{tool_name}")
async def websocket_install(websocket: WebSocket, tool_name: str):
    """Run the install command for a known tool and stream output."""
    await websocket.accept()
    command = _get_install_command(tool_name)
    if not command:
        await websocket.send_json({"type": "error", "data": f"Unknown tool: {tool_name}"})
        await websocket.close()
        return

    try:
        async for message in run_command_streaming(command):
            await websocket.send_json(message)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "data": str(e)})
        except Exception:
            pass


# ── Presence / multi-user awareness ──────────────────────────────────────────
#
# Clients connect to /ws/presence/{project_id}?user=<display_name>
# On connect: announces join to all peers in the project room.
# On disconnect: announces leave.
# Heartbeat ping every 20s keeps the connection alive through proxies.
# Each message received from clients is re-broadcast as-is to all peers
# (supports "cursor" or "typing" events from the frontend).

# Map of project_id → {client_id: {"ws": WebSocket, "user": str, "page": str}}
_presence_rooms: dict[str, dict[str, dict]] = {}


async def _presence_broadcast(project_id: str, event: dict, exclude: str | None = None) -> None:
    """Broadcast a presence event to all clients in a project room."""
    room = _presence_rooms.get(project_id, {})
    dead: list[str] = []
    for cid, info in room.items():
        if cid == exclude:
            continue
        try:
            await info["ws"].send_json(event)
        except Exception:
            dead.append(cid)
    for cid in dead:
        room.pop(cid, None)


@router.websocket("/ws/presence/{project_id}")
async def websocket_presence(websocket: WebSocket, project_id: str, user: str = "anonymous"):
    """
    Real-time presence channel for a project.

    Query params:
      user — display name for this session (defaults to "anonymous")

    Message types sent TO client:
      {"type": "presence_snapshot", "users": [{id, user, page}]}
      {"type": "presence_join",     "id": str, "user": str, "page": str}
      {"type": "presence_leave",    "id": str, "user": str}
      {"type": "presence_update",   "id": str, "user": str, "page": str}
      {"type": "ping"}

    Message types received FROM client:
      {"type": "page", "page": str}  — current page/section the user is on
    """
    await websocket.accept()

    # Sanitise display name
    user = str(user)[:64].strip() or "anonymous"
    client_id = str(uuid.uuid4())

    # Join room
    if project_id not in _presence_rooms:
        _presence_rooms[project_id] = {}
    _presence_rooms[project_id][client_id] = {"ws": websocket, "user": user, "page": ""}

    # Send snapshot of current users to the new joiner
    room = _presence_rooms[project_id]
    snapshot = [
        {"id": cid, "user": info["user"], "page": info["page"]}
        for cid, info in room.items()
        if cid != client_id
    ]
    try:
        await websocket.send_json({"type": "presence_snapshot", "users": snapshot})
    except Exception:
        _presence_rooms[project_id].pop(client_id, None)
        return

    # Announce join to other clients
    await _presence_broadcast(project_id, {
        "type": "presence_join",
        "id": client_id,
        "user": user,
        "page": "",
    }, exclude=client_id)

    try:
        while True:
            try:
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=25.0)
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue
                if msg.get("type") == "page":
                    new_page = str(msg.get("page", ""))[:128]
                    if project_id in _presence_rooms and client_id in _presence_rooms[project_id]:
                        _presence_rooms[project_id][client_id]["page"] = new_page
                    await _presence_broadcast(project_id, {
                        "type": "presence_update",
                        "id": client_id,
                        "user": user,
                        "page": new_page,
                    }, exclude=client_id)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        if project_id in _presence_rooms:
            _presence_rooms[project_id].pop(client_id, None)
            if not _presence_rooms[project_id]:
                del _presence_rooms[project_id]
        # Announce leave
        await _presence_broadcast(project_id, {
            "type": "presence_leave",
            "id": client_id,
            "user": user,
        })



# ── EC2 C2 Provisioning WebSocket ─────────────────────────────────────────────

@router.websocket("/ws/cloud/provision/{instance_db_id}")
async def websocket_cloud_provision(websocket: WebSocket, instance_db_id: str):
    """Stream EC2 C2 node provisioning: poll for running state → wait for SSH → install C2 software."""
    await websocket.accept()
    db = SessionLocal()

    async def send(msg: str, level: str = "info") -> None:
        await websocket.send_json({"type": "stdout", "data": f"[{level.upper()}] {msg}"})

    try:
        from database import CloudC2Instance, C2Node, Credential
        inst = db.query(CloudC2Instance).filter(CloudC2Instance.id == instance_db_id).first()
        if not inst:
            await send("Instance not found", "error")
            return

        if not inst.instance_id:
            await send("No AWS instance ID — was the instance launched?", "error")
            return

        # ── 1. Get boto3 session ────────────────────────────────────────────
        from routers.cloud import _get_boto3_session, _UBUNTU_AMIS
        boto_session = _get_boto3_session(db)
        ec2 = boto_session.client("ec2", region_name=inst.region)

        # ── 2. Poll until running ───────────────────────────────────────────
        await send(f"Waiting for instance {inst.instance_id} to reach running state…")
        inst.status = "launching"
        db.commit()

        for attempt in range(60):  # up to 5 min (5s × 60)
            await asyncio.sleep(5)
            try:
                resp = ec2.describe_instances(InstanceIds=[inst.instance_id])
                state = resp["Reservations"][0]["Instances"][0]["State"]["Name"]
                pub_ip = resp["Reservations"][0]["Instances"][0].get("PublicIpAddress", "")
            except Exception as e:
                await send(f"AWS poll error: {e}", "warning")
                continue

            await send(f"  state={state}  ip={pub_ip or '(pending)'}")
            if state == "running" and pub_ip:
                inst.public_ip = pub_ip
                inst.status = "running"
                db.commit()
                await send(f"Instance is running at {pub_ip}")
                break
        else:
            inst.status = "error"
            inst.error_msg = "Timed out waiting for instance to reach running state"
            db.commit()
            await send("Timed out waiting for running state", "error")
            await websocket.send_json({"type": "exit", "code": 1})
            return

        # ── 3. Wait for SSH ─────────────────────────────────────────────────
        import socket as _socket
        await send(f"Waiting for SSH on {inst.public_ip}:22…")
        inst.status = "configuring"
        db.commit()
        ssh_ready = False
        for _ in range(36):  # up to 3 min
            await asyncio.sleep(5)
            try:
                s = _socket.create_connection((inst.public_ip, 22), timeout=5)
                s.close()
                ssh_ready = True
                break
            except Exception:
                await send("  SSH not yet available, retrying…")
        if not ssh_ready:
            inst.status = "error"
            inst.error_msg = "SSH did not become available"
            db.commit()
            await send("SSH timed out", "error")
            await websocket.send_json({"type": "exit", "code": 1})
            return
        await send("SSH is available!")

        # ── 4. Load SSH key ─────────────────────────────────────────────────
        key_pem = ""
        if inst.ssh_key_credential_id:
            key_cred = db.query(Credential).filter(Credential.id == inst.ssh_key_credential_id).first()
            if key_cred:
                key_pem = key_cred.secret or ""

        # ── 5. Build provisioning script ────────────────────────────────────
        rpc_password = secrets.token_hex(16)

        if inst.c2_type == "msf":
            c2_setup = f"""
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y ufw curl wget
curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | bash
ufw default deny incoming
ufw allow 22/tcp
ufw allow 55553/tcp
ufw allow 4444/tcp
ufw --force enable
msfrpcd -P {rpc_password} -S -a 0.0.0.0 -p 55553 -f &
echo "MSF RPC started on port 55553"
"""
        else:
            c2_setup = f"""
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y ufw curl wget
curl -sSfL https://sliver.sh/install | bash
ufw default deny incoming
ufw allow 22/tcp
ufw allow 31337/tcp
ufw allow 8443/tcp
ufw allow 443/tcp
ufw --force enable
sliver-server daemon --host 0.0.0.0 --port 31337 &
echo "Sliver daemon started on port 31337"
"""

        provision_script = f"""#!/bin/bash
set -e
echo "=== Seraph C2 Provisioning Started ==="
{c2_setup}
echo "=== Provisioning Complete ==="
"""

        # ── 6. Execute over SSH ─────────────────────────────────────────────
        await send(f"Running provisioning script ({inst.c2_type.upper()} setup)…")
        log_lines: list[str] = []
        exit_code = 0
        async for message in run_script_over_ssh(inst.public_ip, "ubuntu", key_pem, provision_script):
            await websocket.send_json(message)
            if message["type"] in ("stdout", "stderr"):
                log_lines.append(message.get("data", ""))
            elif message["type"] == "exit":
                exit_code = message.get("code", 0)

        inst.provision_log = "".join(log_lines)

        if exit_code != 0:
            inst.status = "error"
            inst.error_msg = f"Provisioning script exited with code {exit_code}"
            db.commit()
            await websocket.send_json({"type": "exit", "code": exit_code})
            return

        # ── 7. Register as C2 Node ──────────────────────────────────────────
        msf_port = 55553 if inst.c2_type == "msf" else 31337
        node = C2Node(
            name=inst.name,
            c2_type=inst.c2_type,
            host=inst.public_ip,
            port=msf_port,
            password=rpc_password,
            ssl=True if inst.c2_type == "msf" else False,
            source="ec2",
            cloud_instance_id=inst.id,
            status="unknown",
            notes=f"Provisioned from EC2 instance {inst.instance_id}",
        )
        db.add(node)
        db.flush()

        inst.status = "ready"
        inst.node_id = node.id
        db.commit()

        await send(f"C2 node registered — ID: {node.id}")
        await send(f"Connect to it in the Infrastructure tab.")
        await websocket.send_json({"type": "exit", "code": 0})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "data": str(e)})
            await websocket.send_json({"type": "exit", "code": 1})
        except Exception:
            pass
        try:
            from database import CloudC2Instance
            inst = db.query(CloudC2Instance).filter(CloudC2Instance.id == instance_db_id).first()
            if inst:
                inst.status = "error"
                inst.error_msg = str(e)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()
