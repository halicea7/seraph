"""
Auto-Probe service — fires a lightweight background recon when a target is created.
Each tool runs sequentially in an asyncio coroutine. Results are saved as normal
Scan records with config_json={"auto_probe": true} so the UI can identify them.

Port discovery order:
  1. Rustscan (if available) — fast full-port scan, results fed to nmap -sV
  2. Nmap — service/version detection on ports found by rustscan, or --top-ports 1000 fallback
  3. Nikto / testssl / nuclei / feroxbuster — triggered by open ports
"""
import asyncio
import json
import os
import pathlib
import re
import shutil
import uuid
from datetime import datetime

from database import AppSetting, Finding, Notification, Scan, SessionLocal

# ── Cancellation registry ──────────────────────────────────────────────────
# Maps target_id → running asyncio.Task so cancel_probe() can stop it.
# Maps scan_id   → target_id so we can look up by any scan belonging to the run.
_active_probes: dict[str, "asyncio.Task"] = {}
_scan_to_target: dict[str, str] = {}

# Tool definitions — cmd is a callable(host) -> shell string
# Rustscan is handled separately as a pre-nmap step (see run_auto_probe).
PROBE_STEPS = [
    {
        "name": "whois",
        "scan_type": "whois",
        "cmd": lambda h: f"whois {h}",
        "always": True,
        "trigger_ports": set(),
    },
    {
        "name": "nmap",
        "scan_type": "nmap",
        "cmd": lambda h: f"nmap -sV -T4 --top-ports 1000 {h}",
        "always": True,
        "trigger_ports": set(),
    },
    {
        "name": "wafw00f",
        "scan_type": "wafw00f",
        "cmd": lambda h: f"wafw00f -a http://{h}",
        "always": False,
        "trigger_ports": {80, 443, 8080, 8443, 8000, 8888},
    },
    {
        "name": "nikto",
        "scan_type": "nikto",
        "cmd": lambda h: f"nikto -h {h}",
        "clamp_timeout": True,   # pass -maxtime to cap runtime
        "always": False,
        "trigger_ports": {80, 443, 8080, 8443, 8000},
    },
    {
        "name": "testssl",
        "scan_type": "testssl",
        "cmd": lambda h: f"testssl --fast {h}",
        "always": False,
        "trigger_ports": {443, 8443},
    },
    {
        "name": "nuclei",
        "scan_type": "nuclei",
        # -json for structured output, -silent suppresses banner, -severity medium+ by default
        "cmd": lambda h: f"nuclei -u {h} -j -silent -severity medium,high,critical",
        "always": False,
        "trigger_ports": {80, 443, 8080, 8443, 8000, 8888},
    },
    {
        "name": "feroxbuster",
        "scan_type": "feroxbuster",
        # -q quiet, --no-state no resume file, -d 2 max depth 2
        # wordlist resolved at runtime so we pick whatever is actually installed
        "cmd": lambda h: f"feroxbuster -u http://{h} -q --no-state -d 2 -k -w {_ferox_wordlist()}",
        "always": False,
        "trigger_ports": {80, 8080, 8000, 8888},
    },
]


def _ferox_wordlist() -> str:
    """Return the best available web-content wordlist for feroxbuster."""
    candidates = [
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/dirb/wordlists/common.txt",
        # Seraph's local wordlists dir — user can drop any .txt here
        str(pathlib.Path(__file__).resolve().parents[2] / "wordlists" / "web-content.txt"),
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    # Last resort: generate a minimal built-in list so feroxbuster can still run
    fallback = "/tmp/seraph_ferox_fallback.txt"
    if not os.path.exists(fallback):
        common = [
            "admin", "login", "wp-admin", "api", "config", "backup", "uploads",
            "static", "assets", "images", "js", "css", "robots.txt", ".env",
            "phpinfo.php", "index.php", "shell", "test", "dev", "dashboard",
        ]
        with open(fallback, "w") as f:
            f.write("\n".join(common))
    return fallback

_OPEN_PORT_RE = re.compile(r"(\d+)/tcp\s+open")
_SERVICE_VERSION_RE = re.compile(r"^\s*\d+/tcp\s+open\s+\S+\s+([A-Za-z][^\n]+)", re.MULTILINE)
# Rustscan outputs lines like "Open 192.168.1.1:22" or just port lists
_RUSTSCAN_PORT_RE = re.compile(r"Open\s+[\d.]+:(\d+)|^(\d+)$", re.MULTILINE)


def get_probe_config() -> dict:
    """Read auto-probe settings from the DB."""
    db = SessionLocal()
    try:
        def _get(key: str, default: str) -> str:
            row = db.query(AppSetting).filter(AppSetting.key == key).first()
            return row.value if row else default

        enabled = _get("auto_probe_enabled", "false") == "true"
        tools_raw = _get("auto_probe_tools", '["whois","nmap","nikto","testssl"]')
        try:
            tools: list[str] = json.loads(tools_raw)
        except Exception:
            tools = ["whois", "nmap", "nikto", "testssl"]
        intensity = _get("auto_probe_intensity", "standard")
        return {"enabled": enabled, "tools": tools, "intensity": intensity}
    finally:
        db.close()


# ── Service-fingerprint → tool routing table ──────────────────────────────────
# Each entry: (service_pattern_re, required_tool, scan_type, cmd_template)
# cmd_template receives .format(host=host, port=port)
_SERVICE_ROUTES: list[tuple[re.Pattern, str, str, str]] = [
    # Active Directory — Kerberos
    (re.compile(r"\bkerberos\b|kpasswd", re.I), "nmap",
     "kerberos_probe", "nmap -p {port} --script krb5-enum-users {host}"),
    # Active Directory — LDAP/GC enumeration via nmap NSE
    (re.compile(r"\bldap\b", re.I), "nmap",
     "ldap_nse", "nmap -p {port} --script ldap-rootdse,ldap-search {host}"),
    # Active Directory — full enum4linux (triggers on LDAP service)
    (re.compile(r"\bldap\b", re.I), "enum4linux",
     "ldap_enum", "enum4linux -a {host}"),
    # SMB / NetBIOS enumeration
    (re.compile(r"microsoft-ds|netbios-ssn|smb", re.I), "nxc",
     "smb_enum", "nxc smb {host} --shares --users 2>/dev/null"),
    # FTP anonymous login check via nmap NSE
    (re.compile(r"\bftp\b", re.I), "nmap",
     "ftp_anon", "nmap -p {port} --script ftp-anon,ftp-bounce {host}"),
    # SSH cipher/auth enumeration
    (re.compile(r"\bssh\b", re.I), "nmap",
     "ssh_audit", "nmap -p {port} --script ssh-auth-methods,ssh2-enum-algos {host}"),
    # MySQL info + empty password check
    (re.compile(r"\bmysql\b", re.I), "nmap",
     "mysql_probe", "nmap -p {port} --script mysql-info,mysql-empty-password,mysql-databases {host}"),
    # MSSQL enumeration
    (re.compile(r"\bms-sql|microsoft.*sql|mssql\b", re.I), "nmap",
     "mssql_probe", "nmap -p {port} --script ms-sql-info,ms-sql-empty-password {host}"),
    # RDP encryption check
    (re.compile(r"\bms-wbt-server\b|rdp", re.I), "nmap",
     "rdp_probe", "nmap -p {port} --script rdp-enum-encryption {host}"),
    # SNMP community string brute
    (re.compile(r"\bsnmp\b", re.I), "nmap",
     "snmp_probe", "nmap -sU -p {port} --script snmp-info,snmp-sysdescr {host}"),
    # MongoDB / Redis (common cloud misconfig)
    (re.compile(r"\bmongodb\b", re.I), "nmap",
     "mongodb_probe", "nmap -p {port} --script mongodb-info {host}"),
    (re.compile(r"\bredis\b", re.I), "nmap",
     "redis_probe", "nmap -p {port} --script redis-info {host}"),
]

# AD is confirmed when Kerberos (88) AND LDAP (389/636/3268) AND SMB (445) are all present.
_AD_PORT_SIGNALS = {88, 389, 445}


def _is_active_directory(nmap_output: str) -> bool:
    """Return True if the host looks like an Active Directory DC based on open ports."""
    open_ports = _extract_open_ports(nmap_output)
    return _AD_PORT_SIGNALS.issubset(open_ports)


def _get_ad_enum_steps(target_host: str, enabled_tools: list[str],
                       search_path: str) -> list[tuple[str, str, str]]:
    """
    Return a comprehensive set of (scan_type, cmd, tool_name) AD enumeration steps.
    These supplement the per-service routes and are only triggered when _is_active_directory() is True.
    """
    steps: list[tuple[str, str, str]] = []

    def avail(tool: str) -> bool:
        return tool in enabled_tools and bool(shutil.which(tool, path=search_path))

    # impacket-GetUserSPNs — find Kerberoastable accounts (no creds, just lists)
    if avail("impacket-GetUserSPNs"):
        steps.append((
            "kerberoast_enum",
            f"impacket-GetUserSPNs -no-pass -dc-ip {target_host} 'WORKGROUP/' 2>/dev/null",
            "impacket-GetUserSPNs",
        ))
    # impacket-GetNPUsers — find AS-REP roastable accounts
    if avail("impacket-GetNPUsers"):
        steps.append((
            "asrep_enum",
            f"impacket-GetNPUsers -no-pass -dc-ip {target_host} 'WORKGROUP/' 2>/dev/null",
            "impacket-GetNPUsers",
        ))
    # nxc SMB null session user/group enum
    if avail("nxc"):
        steps.append((
            "ad_null_session",
            f"nxc smb {target_host} -u '' -p '' --users --groups 2>/dev/null",
            "nxc",
        ))
    # nmap AD-specific NSE scripts
    if avail("nmap"):
        steps.append((
            "ad_nse_enum",
            f"nmap -p 88,389,445,3268 --script msrpc-enum,smb-security-mode,smb2-security-mode,ldap-rootdse {target_host}",
            "nmap",
        ))

    return steps


def _get_service_routes(nmap_output: str, target_host: str,
                        enabled_tools: list[str], search_path: str) -> list[tuple[str, str, str]]:
    """Return list of (scan_type, cmd, tool_name) for services detected in nmap output."""
    # Parse service lines: port/proto open  service  version
    svc_re = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", re.MULTILINE)
    added: set[str] = set()
    steps: list[tuple[str, str, str]] = []

    for m in svc_re.finditer(nmap_output):
        port = m.group(1)
        service = m.group(3)
        for pattern, tool, scan_type, cmd_tpl in _SERVICE_ROUTES:
            if pattern.search(service):
                if tool not in enabled_tools:
                    continue
                if not shutil.which(tool, path=search_path):
                    continue
                cmd = cmd_tpl.format(host=target_host, port=port)
                # Deduplicate by exact command string (avoids running enum4linux twice for ldap:389 + ldap:3268)
                if cmd in added:
                    continue
                added.add(cmd)
                steps.append((scan_type, cmd, tool))

    return steps


def _extract_open_ports(nmap_output: str) -> set[int]:
    return {int(m.group(1)) for m in _OPEN_PORT_RE.finditer(nmap_output)}


def _extract_service_terms(nmap_output: str) -> list[str]:
    """Extract 'Product Version' search terms from nmap -sV output."""
    terms: list[str] = []
    seen: set[str] = set()
    for m in _SERVICE_VERSION_RE.finditer(nmap_output):
        raw = re.sub(r"\s*\(.*", "", m.group(1)).strip()  # strip "(Ubuntu)" etc.
        parts = raw.split()
        if len(parts) < 2:
            continue
        # Find the first token that looks like a version number (starts with a digit)
        ver_idx = next((i for i, p in enumerate(parts) if p[0].isdigit()), None)
        if ver_idx is None:
            continue
        product = " ".join(parts[:ver_idx])
        version = re.split(r"[-+~]", parts[ver_idx])[0]  # strip distro suffixes
        term = f"{product} {version}"
        if term not in seen:
            seen.add(term)
            terms.append(term)
    return terms


def _extract_nikto_server(nikto_output: str) -> str | None:
    """Extract the Server: header version reported by nikto."""
    m = re.search(r"\+ Server:\s+([^\n]+)", nikto_output)
    if not m:
        return None
    raw = re.sub(r"\s*\(.*\)", "", m.group(1)).strip().replace("/", " ")
    parts = raw.split()
    if len(parts) < 2:
        return None
    version = re.split(r"[-+~]", parts[1])[0]
    return f"{parts[0]} {version}"


async def _searchsploit_query(term: str) -> list[dict]:
    """Run searchsploit --json for one term, return list of exploit dicts."""
    try:
        proc = await asyncio.create_subprocess_shell(
            f'searchsploit --json "{term}"',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env={**os.environ, "TERM": "dumb"},
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
    except Exception:
        return []
    raw = stdout.decode(errors="replace")
    json_start = raw.find("{")
    if json_start == -1:
        return []
    try:
        return json.loads(raw[json_start:]).get("RESULTS_EXPLOIT", [])
    except Exception:
        return []


async def _run_searchsploit(
    target_id: str,
    nmap_output: str,
    nikto_output: str | None,
    timeout: int,
) -> None:
    """Look up discovered service versions in Exploit-DB and save findings."""
    terms = _extract_service_terms(nmap_output)
    if nikto_output:
        server_term = _extract_nikto_server(nikto_output)
        if server_term and server_term not in terms:
            terms.insert(0, server_term)

    if not terms:
        return

    scan_id = _create_scan(target_id, "searchsploit", "searchsploit")

    capped = terms[:12]
    # Query all terms in parallel — each is a self-contained searchsploit subprocess
    all_exploits = await asyncio.gather(*[_searchsploit_query(t) for t in capped])

    raw_sections: list[str] = []
    by_term: dict[str, list[dict]] = {}

    for term, exploits in zip(capped, all_exploits):
        raw_sections.append(f"=== {term} ({len(exploits)} results) ===")
        if exploits:
            by_term[term] = exploits
            for e in exploits[:5]:
                raw_sections.append(f"  [{e.get('EDB-ID','')}] {e.get('Title','')}")

    full_output = "\n".join(raw_sections)
    total = sum(len(v) for v in by_term.values())

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        scan.raw_output = full_output or "No exploits found for detected services."
        scan.status = "completed"
        scan.started_at = datetime.utcnow()
        scan.completed_at = datetime.utcnow()

        findings_added = 0
        for term, exploits in by_term.items():
            remote = [e for e in exploits if "remote" in e.get("Type", "").lower()]
            severity = "high" if remote else "medium"
            evidence_lines = [
                f"[EDB-{e.get('EDB-ID','')}] {e.get('Title','')} ({e.get('Type','')})"
                for e in exploits[:20]
            ]
            db.add(Finding(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                severity=severity,
                title=f"{len(exploits)} exploit(s) found for {term}",
                description=(
                    f"searchsploit matched {len(exploits)} public exploit(s) for '{term}'. "
                    f"{len(remote)} remote exploit(s) available."
                ),
                evidence="\n".join(evidence_lines),
                remediation=(
                    "Review each exploit on https://exploit-db.com and apply vendor patches "
                    "or mitigating controls for the affected service."
                ),
            ))
            findings_added += 1

        db.commit()

        if findings_added:
            highs = sum(
                1 for exploits in by_term.values()
                if any("remote" in e.get("Type", "").lower() for e in exploits)
            )
            db.add(Notification(
                title=f"Exploit research: {total} exploit(s) across {findings_added} service(s)",
                body=(
                    f"searchsploit found {total} known exploit(s) for services on this target."
                    + (f" {highs} service(s) have remote exploits." if highs else "")
                ),
                type="critical" if highs > 0 else "warning",
                scan_id=scan_id,
            ))
            db.commit()

        from routers.ws import broadcast_event as _broadcast
        asyncio.create_task(_broadcast({
            "type": "scan_update", "scan_id": scan_id, "status": "completed",
            "findings": findings_added,
        }))
    finally:
        db.close()


def _timeout_for_intensity(intensity: str) -> int:
    return {"quick": 120, "standard": 300, "deep": 600}.get(intensity, 300)


def _concurrency_for_intensity(intensity: str) -> int:
    """
    Max concurrent tier-2 tools (nikto/testssl/nuclei/feroxbuster).
    Quick = serial (low footprint), Standard = 2, Deep = unrestricted.
    """
    return {"quick": 1, "standard": 2, "deep": 99}.get(intensity, 2)


async def _run_rustscan(target_host: str, timeout: int) -> set[int]:
    """
    Run rustscan to quickly discover open ports. Returns set of open port numbers.
    Rustscan scans all 65535 ports then outputs 'Open HOST:PORT' lines.
    On failure (tool unavailable, timeout) returns empty set so nmap falls back
    to --top-ports 1000.
    """
    try:
        proc = await asyncio.create_subprocess_shell(
            f"rustscan -a {target_host} --ulimit 5000 -b 1500 -- -sn",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return set()
        output = stdout.decode(errors="replace")
        ports: set[int] = set()
        for m in _RUSTSCAN_PORT_RE.finditer(output):
            p = m.group(1) or m.group(2)
            if p:
                ports.add(int(p))
        return ports
    except Exception:
        return set()


async def _run_step(scan_id: str, cmd: str, scan_type: str, timeout: int, env: dict | None = None) -> str | None:
    """Execute one tool, stream output into the Scan record, auto-parse findings."""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return None
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()

    from routers.ws import broadcast_event as _broadcast
    asyncio.create_task(_broadcast({"type": "scan_update", "scan_id": scan_id, "status": "running"}))

    # Build augmented PATH if caller didn't supply one.
    if env is None:
        from services.tool_registry import _extra_search_paths
        extra = ":".join(_extra_search_paths())
        env = os.environ.copy()
        if extra:
            env["PATH"] = f"{extra}:{env.get('PATH', '')}"

    proc = None
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
        )
        chunks: list[str] = []
        try:
            async for line in proc.stdout:  # type: ignore[union-attr]
                chunks.append(line.decode(errors="replace"))
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
    except asyncio.CancelledError:
        # Task was cancelled — kill the subprocess and propagate the cancellation.
        if proc is not None and proc.returncode is None:
            proc.kill()
        raise
    except Exception as exc:
        _mark_failed(scan_id, str(exc))
        return None

    output = "".join(chunks)
    status = "completed"
    finding_count = 0

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            if scan.status == "cancelled":
                # User cancelled while the tool was running — preserve that status.
                return None
            scan.raw_output = output
            scan.status = "completed"
            scan.completed_at = datetime.utcnow()
            db.commit()

            # Auto-parse findings — deduplicate by title within the same target
            from services.output_parser import auto_parse_scan_output
            parsed = auto_parse_scan_output(scan_type, output)
            if parsed:
                existing_titles: set[str] = {
                    row[0] for row in
                    db.query(Finding.title)
                    .join(Scan, Finding.scan_id == Scan.id)
                    .filter(Scan.target_id == scan.target_id)
                    .all()
                }
                new_findings = [pf for pf in parsed if pf.title not in existing_titles]
            else:
                new_findings = []
            for pf in new_findings:
                db.add(Finding(
                    id=str(uuid.uuid4()),
                    scan_id=scan_id,
                    severity=pf.severity,
                    title=pf.title,
                    description=pf.description,
                    control_id=pf.control_id,
                    framework=pf.framework,
                    remediation=pf.remediation,
                    evidence=pf.evidence,
                ))
            if new_findings:
                highs = sum(1 for p in new_findings if p.severity in ("critical", "high"))
                db.add(Notification(
                    title=f"Auto-probe complete — {len(new_findings)} finding(s)",
                    body=f"{scan_type}: {len(new_findings)} finding(s)" + (f", {highs} critical/high" if highs else ""),
                    type="critical" if highs > 0 else "info",
                    scan_id=scan_id,
                ))
            db.commit()
            status = scan.status
            finding_count = len(new_findings)
    finally:
        db.close()

    asyncio.create_task(_broadcast({
        "type": "scan_update", "scan_id": scan_id, "status": status,
        "findings": finding_count,
    }))

    return output


def _mark_failed(scan_id: str, reason: str):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.raw_output = reason
            scan.completed_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


def _create_scan(target_id: str, scan_type: str, tool_name: str) -> str:
    db = SessionLocal()
    try:
        scan = Scan(
            id=str(uuid.uuid4()),
            target_id=target_id,
            scan_type=scan_type,
            module="pentest",
            status="pending",
            config_json=json.dumps({"auto_probe": True, "tool": tool_name}),
        )
        db.add(scan)
        db.commit()
        _scan_to_target[scan.id] = target_id
        return scan.id
    finally:
        db.close()


def cancel_probe(scan_id: str) -> bool:
    """Cancel the running auto-probe task that owns scan_id.

    Returns True if a live task was found and cancelled.
    Safe to call even if the scan is not an auto-probe or has already finished.
    """
    target_id = _scan_to_target.pop(scan_id, None)
    if not target_id:
        return False
    task = _active_probes.get(target_id)
    if task and not task.done():
        task.cancel()
        return True
    return False


async def run_auto_probe(target_id: str, target_host: str, enabled_tools: list[str], intensity: str):
    """
    Main probe coroutine. Tools run in dependency tiers so independent work
    overlaps:

      Tier 0 (parallel): rustscan + whois
      Tier 1 (serial):   nmap  (uses rustscan ports when available)
      Tier 2 (parallel): nikto, testssl, nuclei, feroxbuster  (triggered by nmap ports)
      Tier 3 (serial):   searchsploit  (needs nmap + nikto output)

    searchsploit's internal per-service queries are also parallelised.
    """
    _active_probes[target_id] = asyncio.current_task()  # type: ignore[assignment]
    try:
        from services.tool_registry import _extra_search_paths

        # Look up target type for cloud-specific routing; enforce project scope
        _target_type: str | None = None
        _tdb = SessionLocal()
        try:
            from database import Target as _Target, Project as _Project
            from services.scope_service import check_scope as _check_scope
            _t = _tdb.query(_Target).filter(_Target.id == target_id).first()
            _target_type = _t.target_type if _t else None
            if _t and _t.project_id:
                _proj = _tdb.query(_Project).filter(_Project.id == _t.project_id).first()
                if _proj:
                    in_scope, reason = _check_scope(target_host, _proj.scope_json)
                    if not in_scope:
                        db = SessionLocal()
                        try:
                            scan = _create_scan(db, target_id, {})
                            scan.status = "failed"
                            scan.raw_output = f"Scope enforcement: target {target_host!r} is out of scope. {reason}"
                            db.commit()
                        finally:
                            db.close()
                        return  # abort — out of scope
        finally:
            _tdb.close()

        timeout = _timeout_for_intensity(intensity)
        max_concurrent = _concurrency_for_intensity(intensity)

        # Build the augmented PATH once; reuse for all subprocess calls.
        extra = ":".join(_extra_search_paths())
        env = os.environ.copy()
        if extra:
            env["PATH"] = f"{extra}:{env.get('PATH', '')}"
        search_path = env["PATH"]

        def available(name: str) -> bool:
            return name in enabled_tools and bool(shutil.which(name, path=search_path))

        # ── API target: nuclei API templates + ffuf endpoint fuzzing ─────────────
        if _target_type == "api_endpoint":
            _api_base = target_host if target_host.startswith("http") else f"https://{target_host}"
            if available("nuclei"):
                sid = _create_scan(target_id, "nuclei_api", "nuclei")
                await _run_step(
                    sid,
                    f"nuclei -u {_api_base} -j -silent -severity medium,high,critical -tags api,token,auth,swagger,graphql",
                    "nuclei_api", timeout, env,
                )
            if available("ffuf"):
                sid = _create_scan(target_id, "api_fuzz", "ffuf")
                await _run_step(
                    sid,
                    f"ffuf -u {_api_base}/FUZZ -w {_ferox_wordlist()} -mc 200,201,204,401,403 -o /dev/null -of json 2>&1",
                    "api_fuzz", timeout, env,
                )
            if available("nmap"):
                sid = _create_scan(target_id, "nmap", "nmap")
                await _run_step(sid, f"nmap -sV -T4 -p 443,80,8443,8080,8000,3000,5000 {target_host}", "nmap", timeout, env)

        # ── Cloud target: metadata endpoint check + provider-specific nmap ────────
        if _target_type in ("cloud_aws", "cloud_azure", "cloud_gcp"):
            _cloud_meta_cmds: list[tuple[str, str]] = []
            if _target_type == "cloud_aws":
                _cloud_meta_cmds = [
                    ("cloud_meta", f"curl -sm 5 http://169.254.169.254/latest/meta-data/ 2>&1 || echo 'no metadata endpoint'"),
                    ("cloud_enum", f"nmap -sV -T4 -p 443,80,8443,8080 {target_host}") if available("nmap") else None,
                ]
            elif _target_type == "cloud_azure":
                _cloud_meta_cmds = [
                    ("cloud_meta", f"curl -sm 5 -H 'Metadata:true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' 2>&1 || echo 'no metadata endpoint'"),
                    ("cloud_enum", f"nmap -sV -T4 -p 443,80,8443,22 {target_host}") if available("nmap") else None,
                ]
            elif _target_type == "cloud_gcp":
                _cloud_meta_cmds = [
                    ("cloud_meta", f"curl -sm 5 -H 'Metadata-Flavor: Google' 'http://169.254.169.254/computeMetadata/v1/?recursive=true' 2>&1 || echo 'no metadata endpoint'"),
                    ("cloud_enum", f"nmap -sV -T4 -p 443,80,8080,22 {target_host}") if available("nmap") else None,
                ]
            for item in _cloud_meta_cmds:
                if item is None:
                    continue
                scan_type_c, cmd_c = item
                sid = _create_scan(target_id, scan_type_c, scan_type_c)
                await _run_step(sid, cmd_c, scan_type_c, timeout, env)

        # ── Tier 0: rustscan ∥ whois ──────────────────────────────────────────────
        async def _tier0_rustscan() -> set[int]:
            if available("rustscan"):
                return await _run_rustscan(target_host, timeout)
            return set()

        async def _tier0_whois() -> None:
            if available("whois"):
                scan_id = _create_scan(target_id, "whois", "whois")
                await _run_step(scan_id, f"whois {target_host}", "whois", timeout, env)

        rustscan_ports, _ = await asyncio.gather(_tier0_rustscan(), _tier0_whois())

        # ── Tier 1: nmap (needs rustscan ports) ───────────────────────────────────
        nmap_output: str | None = None
        if available("nmap"):
            scan_id = _create_scan(target_id, "nmap", "nmap")
            if rustscan_ports:
                port_list = ",".join(str(p) for p in sorted(rustscan_ports))
                cmd = f"nmap -sV -T4 -p {port_list} {target_host}"
            else:
                cmd = f"nmap -sV -T4 --top-ports 1000 {target_host}"
            nmap_output = await _run_step(scan_id, cmd, "nmap", timeout, env)

            if nmap_output:
                service_terms = _extract_service_terms(nmap_output)
                if service_terms:
                    from services.cve_watcher import populate_watched_services
                    populate_watched_services(target_id, service_terms)

        # ── Tier 2: conditional tools — concurrency gated by intensity ────────────
        # Quick=1 (serial, low footprint), Standard=2, Deep=unrestricted.
        nikto_output: str | None = None
        if nmap_output:
            open_ports = _extract_open_ports(nmap_output)
            conditional_steps = [s for s in PROBE_STEPS if not s["always"]]
            sem = asyncio.Semaphore(max_concurrent)

            async def _run_conditional(step: dict):
                name = step["name"]
                if not available(name):
                    return name, None
                if not open_ports.intersection(step["trigger_ports"]):
                    return name, None
                sid = _create_scan(target_id, step["scan_type"], name)
                cmd = step["cmd"](target_host)
                if step.get("clamp_timeout"):
                    cmd = f"{cmd} -maxtime {timeout}"
                async with sem:
                    output = await _run_step(sid, cmd, step["scan_type"], timeout, env)
                return name, output

            results = await asyncio.gather(*[_run_conditional(s) for s in conditional_steps])
            for name, output in results:
                if name == "nikto" and output:
                    nikto_output = output

        # ── Tier 2b: service-fingerprint-routed steps ─────────────────────────────
        if nmap_output:
            routed = _get_service_routes(nmap_output, target_host, enabled_tools, search_path)

            # Append AD-specific enumeration if this looks like a domain controller
            if _is_active_directory(nmap_output):
                routed += _get_ad_enum_steps(target_host, enabled_tools, search_path)

            if routed:
                async def _run_routed(scan_type: str, cmd: str, tool: str):
                    sid = _create_scan(target_id, scan_type, tool)
                    async with sem:
                        await _run_step(sid, cmd, scan_type, timeout, env)

                await asyncio.gather(*[_run_routed(st, cmd, tn) for st, cmd, tn in routed])

        # ── Tier 3: searchsploit (needs nmap + nikto) ─────────────────────────────
        if available("searchsploit") and nmap_output:
            await _run_searchsploit(target_id, nmap_output, nikto_output, timeout)

    except asyncio.CancelledError:
        pass  # subprocesses were already killed in _run_step; DB status set by cancel endpoint
    finally:
        _active_probes.pop(target_id, None)


