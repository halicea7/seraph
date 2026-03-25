"""
Playbook execution engine.

Execution model:
  - Steps are grouped into sequential "slots".
  - Steps with parallel=True join the previous slot (asyncio.gather).
  - Sequential slots execute one after the other.
  - Step-through mode pauses before each slot (not before each individual step).
  - AI analysis fires after each slot; in step-through it is awaited so the
    insight is visible in the pause card before the analyst clicks Continue.
"""
import asyncio
import json
import re
import shutil
import uuid
from datetime import datetime
from typing import Awaitable, Callable, Optional

from database import Finding, PlaybookRun, Scan, SessionLocal

SendFn = Callable[[dict], Awaitable[None]]

_OPEN_PORT_RE = re.compile(r"(\d+)/tcp\s+open")

# Per-run events for step-through "continue" signalling
_continue_events: dict[str, asyncio.Event] = {}


def get_continue_event(run_id: str) -> asyncio.Event:
    if run_id not in _continue_events:
        _continue_events[run_id] = asyncio.Event()
    return _continue_events[run_id]


def signal_continue(run_id: str):
    evt = _continue_events.get(run_id)
    if evt:
        evt.set()


def cleanup_run(run_id: str):
    _continue_events.pop(run_id, None)


# ── Built-in playbook definitions ──────────────────────────────────────────────

BUILTIN_PLAYBOOKS = [
    {
        "id": "builtin-full-recon",
        "name": "Full Recon",
        "description": "Comprehensive reconnaissance: domain info, port scan, subdomain and email harvesting.",
        "steps": [
            {"name": "whois",        "scan_type": "whois",        "cmd_template": "whois {target}",                               "description": "Domain ownership & registrar info",  "conditional": False, "trigger_ports": [], "timeout": 30,  "parallel": False},
            {"name": "nmap",         "scan_type": "nmap",         "cmd_template": "nmap -sV -T4 --top-ports 1000 {target}",      "description": "Port scan & service fingerprinting", "conditional": False, "trigger_ports": [], "timeout": 300, "parallel": False},
            {"name": "subfinder",    "scan_type": "subfinder",    "cmd_template": "subfinder -d {target} -silent",               "description": "Subdomain enumeration",              "conditional": False, "trigger_ports": [], "timeout": 120, "parallel": True},
            {"name": "theHarvester", "scan_type": "theHarvester", "cmd_template": "theHarvester -d {target} -b all -l 100",     "description": "Email & subdomain harvesting",       "conditional": False, "trigger_ports": [], "timeout": 120, "parallel": True},
        ],
    },
    {
        "id": "builtin-web-sweep",
        "name": "Web App Sweep",
        "description": "Web application assessment: port detection, vuln scan, directory brute-force, SSL audit.",
        "steps": [
            {"name": "nmap",     "scan_type": "nmap",     "cmd_template": "nmap -sV -p 80,443,8080,8443,8000 {target}",                           "description": "Web port detection",            "conditional": False, "trigger_ports": [],                    "timeout": 60,  "parallel": False},
            {"name": "nikto",    "scan_type": "nikto",    "cmd_template": "nikto -h {target}",                                                    "description": "Web server vulnerability scan", "conditional": True,  "trigger_ports": [80, 443, 8080, 8443], "timeout": 300, "parallel": False},
            {"name": "gobuster", "scan_type": "gobuster", "cmd_template": "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -q", "description": "Directory & file brute-force", "conditional": True, "trigger_ports": [80, 8080, 8000],     "timeout": 300, "parallel": True},
            {"name": "testssl",  "scan_type": "testssl",  "cmd_template": "testssl --fast {target}",                                              "description": "TLS/SSL configuration audit",   "conditional": True,  "trigger_ports": [443, 8443],           "timeout": 180, "parallel": False},
        ],
    },
    {
        "id": "builtin-ad-audit",
        "name": "AD / SMB Audit",
        "description": "Active Directory and SMB enumeration for Windows network environments.",
        "steps": [
            {"name": "nmap",       "scan_type": "nmap",      "cmd_template": "nmap -sV -p 139,445,389,636,3389 {target}", "description": "SMB/AD port detection",      "conditional": False, "trigger_ports": [],         "timeout": 60,  "parallel": False},
            {"name": "enum4linux", "scan_type": "enum4linux", "cmd_template": "enum4linux -a {target}",                   "description": "SMB/NetBIOS/AD enumeration", "conditional": True,  "trigger_ports": [139, 445], "timeout": 300, "parallel": False},
        ],
    },
    {
        "id": "builtin-vuln-assess",
        "name": "Vuln Assessment",
        "description": "Vulnerability identification via NSE scripts, exploit lookup, and SQL injection testing.",
        "steps": [
            {"name": "nmap",         "scan_type": "nmap",        "cmd_template": "nmap -sV --script=vuln {target}",       "description": "Vulnerability NSE scan",   "conditional": False, "trigger_ports": [],             "timeout": 600, "parallel": False},
            {"name": "searchsploit", "scan_type": "searchsploit","cmd_template": "searchsploit {target}",                 "description": "Exploit database lookup",   "conditional": False, "trigger_ports": [],             "timeout": 30,  "parallel": True},
            {"name": "sqlmap",       "scan_type": "sqlmap",      "cmd_template": "sqlmap -u http://{target} --batch -q", "description": "SQL injection detection",   "conditional": True,  "trigger_ports": [80, 443, 8080],"timeout": 300, "parallel": False},
        ],
    },
    {
        "id": "builtin-osint",
        "name": "OSINT Deep Dive",
        "description": "Open-source intelligence: domain info, email harvesting, passive subdomain enumeration.",
        "steps": [
            {"name": "whois",        "scan_type": "whois",        "cmd_template": "whois {target}",                          "description": "Domain & ASN registration info", "conditional": False, "trigger_ports": [], "timeout": 30,  "parallel": False},
            {"name": "theHarvester", "scan_type": "theHarvester", "cmd_template": "theHarvester -d {target} -b all -l 200", "description": "Email & subdomain harvesting",   "conditional": False, "trigger_ports": [], "timeout": 180, "parallel": False},
            {"name": "amass",        "scan_type": "amass",        "cmd_template": "amass enum -passive -d {target}",        "description": "Passive subdomain enumeration",  "conditional": False, "trigger_ports": [], "timeout": 300, "parallel": True},
            {"name": "subfinder",    "scan_type": "subfinder",    "cmd_template": "subfinder -d {target} -silent",          "description": "Subdomain enumeration",          "conditional": False, "trigger_ports": [], "timeout": 120, "parallel": True},
        ],
    },
    {
        "id": "builtin-web-full",
        "name": "Web App Full Assessment",
        "description": "Comprehensive web assessment: fingerprinting, vuln scan, directory brute-force, fuzzing, injection, and SSL audit.",
        "steps": [
            {"name": "nmap",     "scan_type": "nmap",     "cmd_template": "nmap -sV -p 80,443,8080,8443,8000,8888 {target}",                                    "description": "Web service detection",         "conditional": False, "trigger_ports": [],                       "timeout": 60,  "parallel": False},
            {"name": "whatweb",  "scan_type": "whatweb",  "cmd_template": "whatweb -a 3 http://{target}",                                                        "description": "Web technology fingerprinting", "conditional": True,  "trigger_ports": [80, 8080, 8000, 8888],   "timeout": 30,  "parallel": False},
            {"name": "nikto",    "scan_type": "nikto",    "cmd_template": "nikto -h {target}",                                                                   "description": "Web server vulnerability scan", "conditional": True,  "trigger_ports": [80, 443, 8080, 8443],    "timeout": 300, "parallel": False},
            {"name": "gobuster", "scan_type": "gobuster", "cmd_template": "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -q",          "description": "Directory & file brute-force",  "conditional": True,  "trigger_ports": [80, 8080, 8000],         "timeout": 300, "parallel": True},
            {"name": "wfuzz",    "scan_type": "wfuzz",    "cmd_template": "wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt --hc 404 http://{target}/FUZZ", "description": "Parameter & path fuzzing",      "conditional": True,  "trigger_ports": [80, 443, 8080],          "timeout": 300, "parallel": True},
            {"name": "sqlmap",   "scan_type": "sqlmap",   "cmd_template": "sqlmap -u http://{target} --batch -q --level=1",                                      "description": "SQL injection detection",        "conditional": True,  "trigger_ports": [80, 443, 8080],          "timeout": 300, "parallel": False},
            {"name": "testssl",  "scan_type": "testssl",  "cmd_template": "testssl --fast {target}",                                                             "description": "TLS/SSL configuration audit",   "conditional": True,  "trigger_ports": [443, 8443],              "timeout": 180, "parallel": True},
        ],
    },
    {
        "id": "builtin-api-sec",
        "name": "API Security Test",
        "description": "REST API security assessment: endpoint discovery, injection testing, and authentication probing.",
        "steps": [
            {"name": "nmap",     "scan_type": "nmap",     "cmd_template": "nmap -sV -p 80,443,8080,8443,3000,5000,8000 {target}",                                    "description": "API service port detection",  "conditional": False, "trigger_ports": [],                             "timeout": 60,  "parallel": False},
            {"name": "gobuster", "scan_type": "gobuster", "cmd_template": "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -x json,xml -q", "description": "API endpoint discovery",       "conditional": True,  "trigger_ports": [80, 8080, 3000, 5000, 8000],   "timeout": 300, "parallel": False},
            {"name": "nikto",    "scan_type": "nikto",    "cmd_template": "nikto -h {target} -Tuning 9",                                                            "description": "API vulnerability scan",       "conditional": True,  "trigger_ports": [80, 443, 8080, 8443],          "timeout": 300, "parallel": True},
            {"name": "sqlmap",   "scan_type": "sqlmap",   "cmd_template": "sqlmap -u http://{target}/api --batch -q --level=2 --risk=1",                            "description": "API SQL injection detection",  "conditional": True,  "trigger_ports": [80, 443, 8080],                "timeout": 300, "parallel": False},
        ],
    },
    {
        "id": "builtin-ad-attack",
        "name": "Active Directory Attack Chain",
        "description": "Full AD attack path: port detection, domain enumeration, SMB mapping, Kerberoasting, and AS-REP roasting.",
        "steps": [
            {"name": "nmap",                 "scan_type": "nmap",        "cmd_template": "nmap -sV -p 88,389,445,636,3268,3269,3389 {target}",                       "description": "DC / AD service detection",       "conditional": False, "trigger_ports": [],         "timeout": 60,  "parallel": False},
            {"name": "enum4linux",           "scan_type": "enum4linux",  "cmd_template": "enum4linux -a -M -l -d {target}",                                         "description": "Domain & user enumeration",       "conditional": True,  "trigger_ports": [139, 445], "timeout": 300, "parallel": False},
            {"name": "crackmapexec",         "scan_type": "crackmapexec","cmd_template": "crackmapexec smb {target} --shares --sessions --disks",                   "description": "SMB share & session enumeration", "conditional": True,  "trigger_ports": [445],      "timeout": 120, "parallel": True},
            {"name": "impacket-GetUserSPNs", "scan_type": "kerberoast",  "cmd_template": "impacket-GetUserSPNs -dc-ip {target} {target}/ -no-pass",                "description": "Kerberoasting: SPN enumeration",  "conditional": True,  "trigger_ports": [88, 389],  "timeout": 60,  "parallel": False},
            {"name": "impacket-GetNPUsers",  "scan_type": "asreproast",  "cmd_template": "impacket-GetNPUsers -dc-ip {target} {target}/ -no-pass -format hashcat", "description": "AS-REP Roasting",                 "conditional": True,  "trigger_ports": [88],       "timeout": 60,  "parallel": True},
        ],
    },
    {
        "id": "builtin-postex-linux",
        "name": "Post-Exploitation: Linux",
        "description": "Linux post-exploitation via SSH: system enum, SUID discovery, sudo audit, cron jobs, and credential file search.",
        "steps": [
            {"name": "ssh",  "scan_type": "postex", "cmd_template": "ssh -o StrictHostKeyChecking=no -o BatchMode=yes {target} 'id; uname -a; cat /etc/os-release 2>/dev/null; whoami; hostname; ip addr 2>/dev/null || ifconfig 2>/dev/null'",                                                                                  "description": "System info & network identity",       "conditional": False, "trigger_ports": [],   "timeout": 30, "parallel": False},
            {"name": "find", "scan_type": "postex", "cmd_template": "ssh -o StrictHostKeyChecking=no -o BatchMode=yes {target} 'find / -perm -u=s -type f 2>/dev/null; echo \"---SGID---\"; find / -perm -g=s -type f 2>/dev/null'",                                                                                           "description": "SUID/SGID binary discovery",           "conditional": True,  "trigger_ports": [22], "timeout": 60, "parallel": False},
            {"name": "sudo", "scan_type": "postex", "cmd_template": "ssh -o StrictHostKeyChecking=no -o BatchMode=yes {target} 'sudo -l 2>/dev/null; echo \"---SUDOERS---\"; cat /etc/sudoers 2>/dev/null | grep -v \"^#\" | grep -v \"^$\" | head -30'",                                                                    "description": "Sudo permissions & sudoers audit",     "conditional": True,  "trigger_ports": [22], "timeout": 30, "parallel": True},
            {"name": "grep", "scan_type": "postex", "cmd_template": "ssh -o StrictHostKeyChecking=no -o BatchMode=yes {target} 'crontab -l 2>/dev/null; ls -la /etc/cron* 2>/dev/null; grep -r \"password\" /home 2>/dev/null | head -20; find /home -name \"*.key\" -o -name \"id_rsa\" 2>/dev/null'",                     "description": "Cron jobs, credentials & SSH keys",    "conditional": True,  "trigger_ports": [22], "timeout": 30, "parallel": True},
        ],
    },
    {
        "id": "builtin-postex-windows",
        "name": "Post-Exploitation: Windows",
        "description": "Windows post-exploitation using Impacket & CrackMapExec: credential dumping, SAM/NTDS extraction, LSA secret harvesting.",
        "steps": [
            {"name": "nmap",                 "scan_type": "nmap",        "cmd_template": "nmap -sV -p 445,135,139,3389,5985,5986 {target}",  "description": "Windows admin service detection",  "conditional": False, "trigger_ports": [],    "timeout": 60,  "parallel": False},
            {"name": "impacket-secretsdump", "scan_type": "secretsdump", "cmd_template": "impacket-secretsdump -no-pass {target}",            "description": "SAM/NTDS credential dump",         "conditional": True,  "trigger_ports": [445], "timeout": 120, "parallel": False},
            {"name": "crackmapexec",         "scan_type": "crackmapexec","cmd_template": "crackmapexec smb {target} --sam --lsa",             "description": "SAM & LSA secret extraction",      "conditional": True,  "trigger_ports": [445], "timeout": 120, "parallel": True},
        ],
    },
    {
        "id": "builtin-postex-lateral",
        "name": "Post-Exploitation: Lateral Movement",
        "description": "Internal network discovery and lateral movement: host sweep, service mapping, SMB relay target identification.",
        "steps": [
            {"name": "nmap",         "scan_type": "nmap",        "cmd_template": "nmap -sn {target}/24 --open",                                       "description": "Internal host sweep (/24)",        "conditional": False, "trigger_ports": [], "timeout": 120, "parallel": False},
            {"name": "nmap",         "scan_type": "nmap",        "cmd_template": "nmap -sV --top-ports 100 --open -T4 {target}/24",                   "description": "Service scan on discovered hosts", "conditional": False, "trigger_ports": [], "timeout": 600, "parallel": False},
            {"name": "crackmapexec", "scan_type": "crackmapexec","cmd_template": "crackmapexec smb {target}/24 --gen-relay-list /tmp/relay_list.txt", "description": "SMB relay / signing audit",        "conditional": False, "trigger_ports": [], "timeout": 120, "parallel": True},
        ],
    },
    {
        "id": "builtin-db-enum",
        "name": "Database Enumeration",
        "description": "Database service discovery across MySQL, PostgreSQL, MSSQL, MongoDB, Redis with basic authentication probing.",
        "steps": [
            {"name": "nmap",   "scan_type": "nmap",   "cmd_template": "nmap -sV -p 3306,5432,1433,1521,27017,6379,9200,5984 --script=banner {target}",   "description": "Database port & banner detection",   "conditional": False, "trigger_ports": [],              "timeout": 60,  "parallel": False},
            {"name": "nmap",   "scan_type": "nmap",   "cmd_template": "nmap --script=mysql-info,mysql-databases,mysql-users -p 3306 {target}",           "description": "MySQL service enumeration",          "conditional": True,  "trigger_ports": [3306],          "timeout": 60,  "parallel": False},
            {"name": "nmap",   "scan_type": "nmap",   "cmd_template": "nmap --script=ms-sql-info,ms-sql-config,ms-sql-empty-password -p 1433 {target}",  "description": "MSSQL service enumeration",          "conditional": True,  "trigger_ports": [1433],          "timeout": 60,  "parallel": True},
            {"name": "sqlmap", "scan_type": "sqlmap", "cmd_template": "sqlmap -u http://{target} --batch --dbs --level=2",                               "description": "Web-facing SQL injection → DB dump", "conditional": True,  "trigger_ports": [80, 443, 8080], "timeout": 300, "parallel": False},
        ],
    },
    {
        "id": "builtin-passwd-spray",
        "name": "Password Spray",
        "description": "Credential spraying across common auth services: SSH via Hydra, SMB via CrackMapExec.",
        "steps": [
            {"name": "nmap",         "scan_type": "nmap",        "cmd_template": "nmap -sV -p 22,445,3389,389,80,443 {target}",                                                                                             "description": "Auth service detection", "conditional": False, "trigger_ports": [],    "timeout": 60,  "parallel": False},
            {"name": "hydra",        "scan_type": "hydra",       "cmd_template": "hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -p Password123 ssh://{target} -t 4 -q",                                "description": "SSH password spray",     "conditional": True,  "trigger_ports": [22],  "timeout": 300, "parallel": False},
            {"name": "crackmapexec", "scan_type": "crackmapexec","cmd_template": "crackmapexec smb {target} -u /usr/share/seclists/Usernames/top-usernames-shortlist.txt -p Password123 --continue-on-success",             "description": "SMB password spray",     "conditional": True,  "trigger_ports": [445], "timeout": 300, "parallel": True},
        ],
    },
    {
        "id": "builtin-cloud-recon",
        "name": "Cloud / Container Recon",
        "description": "Cloud and container recon: exposed Docker/K8s APIs, anonymous access checks, container image vulnerability scanning.",
        "steps": [
            {"name": "nmap", "scan_type": "nmap",   "cmd_template": "nmap -sV -p 2375,2376,2377,6443,8443,10250,10255,4001,2379 {target}",                                                                             "description": "Container & K8s port detection",     "conditional": False, "trigger_ports": [],                "timeout": 60,  "parallel": False},
            {"name": "curl", "scan_type": "postex", "cmd_template": "curl -sk http://{target}:2375/version 2>&1 | head -20; curl -sk https://{target}:2376/version --insecure 2>&1 | head -20",                        "description": "Docker API exposure check",           "conditional": True,  "trigger_ports": [2375, 2376],      "timeout": 30,  "parallel": False},
            {"name": "curl", "scan_type": "postex", "cmd_template": "curl -sk https://{target}:6443/api/v1/namespaces --insecure 2>&1 | head -30; curl -sk http://{target}:10255/pods 2>&1 | head -20",               "description": "K8s API anonymous access check",      "conditional": True,  "trigger_ports": [6443, 10255],     "timeout": 30,  "parallel": True},
            {"name": "trivy","scan_type": "trivy",  "cmd_template": "trivy image --timeout 5m {target}",                                                                                                               "description": "Container image vulnerability scan", "conditional": False, "trigger_ports": [],                "timeout": 300, "parallel": False},
        ],
    },
    {
        "id": "builtin-wireless",
        "name": "Wireless Recon",
        "description": "802.11 wireless AP recon: management interface scanning, web probing, WPS detection, and client capture.",
        "steps": [
            {"name": "nmap",        "scan_type": "nmap",     "cmd_template": "nmap -sV -p 80,443,8080,8443 {target}",                                            "description": "AP management interface scan",        "conditional": False, "trigger_ports": [],               "timeout": 60,  "parallel": False},
            {"name": "nikto",       "scan_type": "nikto",    "cmd_template": "nikto -h http://{target}",                                                         "description": "AP web interface vulnerability scan", "conditional": True,  "trigger_ports": [80, 8080, 8443], "timeout": 120, "parallel": True},
            {"name": "wash",        "scan_type": "wireless", "cmd_template": "wash -i wlan0mon --scan 2>/dev/null | head -30",                                    "description": "WPS-enabled AP detection",            "conditional": False, "trigger_ports": [],               "timeout": 30,  "parallel": False},
            {"name": "airodump-ng", "scan_type": "wireless", "cmd_template": "timeout 30 airodump-ng wlan0mon --bssid {target} -w /tmp/seraph_cap 2>/dev/null",  "description": "Client & handshake capture (30s)",    "conditional": False, "trigger_ports": [],               "timeout": 45,  "parallel": False},
        ],
    },
]


def seed_builtin_playbooks():
    """Insert built-in playbooks if they don't already exist. Called at startup."""
    from database import Playbook
    db = SessionLocal()
    try:
        for bp in BUILTIN_PLAYBOOKS:
            existing = db.query(Playbook).filter(Playbook.id == bp["id"]).first()
            if not existing:
                db.add(Playbook(
                    id=bp["id"],
                    name=bp["name"],
                    description=bp["description"],
                    steps_json=json.dumps(bp["steps"]),
                    is_builtin=True,
                ))
        db.commit()
    finally:
        db.close()


# ── Execution group helpers ────────────────────────────────────────────────────

def _build_execution_groups(flat_steps: list[dict]) -> list[list[tuple[int, dict]]]:
    """Group steps into sequential execution slots.

    A step with ``parallel=True`` joins the previous slot so it runs
    concurrently with the steps already in that slot.  Any other step
    (including the very first) starts a new sequential slot.

    Returns a list of groups; each group is a list of (original_index, step).
    """
    groups: list[list[tuple[int, dict]]] = []
    for i, step in enumerate(flat_steps):
        if step.get("parallel") and groups:
            groups[-1].append((i, step))
        else:
            groups.append([(i, step)])
    return groups


# ── AI analysis helpers ─────────────────────────────────────────────────────────

async def _ai_analyze_step(tool: str, target_host: str, step_desc: str, output: str) -> str:
    from database import AppSetting
    db = SessionLocal()
    try:
        def _get(key: str, default: str) -> str:
            row = db.query(AppSetting).filter(AppSetting.key == key).first()
            return row.value if row else default
        endpoint = _get("ai_endpoint", "")
        model = _get("ai_model", "")
    finally:
        db.close()

    if not endpoint or not model:
        return ""

    snippet = output[-3000:] if len(output) > 3000 else output
    messages = [
        {
            "role": "system",
            "content": (
                "You are a concise security analyst assistant embedded in a penetration testing platform. "
                "Analyze tool output and respond in 3-4 sentences maximum. "
                "Format: Key finding | Risk: <Critical/High/Medium/Low/Info> | Next step."
            ),
        },
        {
            "role": "user",
            "content": (
                f"Tool: {tool}\nTarget: {target_host}\nStep: {step_desc}\n\n"
                f"Output:\n{snippet}\n\n"
                "Provide a brief analyst insight: what was found, risk level, recommended next action."
            ),
        },
    ]
    loop = asyncio.get_event_loop()
    try:
        from services.ai_client import chat_complete
        return (await loop.run_in_executor(
            None, lambda: chat_complete(endpoint, model, messages, timeout=60)
        )).strip()
    except Exception:
        return ""


async def _send_ai_insight(step: int, tool: str, target_host: str, step_desc: str,
                            output: str, send: SendFn):
    insight = await _ai_analyze_step(tool, target_host, step_desc, output)
    if insight:
        await send({"type": "step_ai", "step": step, "tool": tool, "insight": insight})


# ── DB helpers ─────────────────────────────────────────────────────────────────

def _extract_open_ports(output: str) -> set[int]:
    return {int(m.group(1)) for m in _OPEN_PORT_RE.finditer(output)}


def _create_scan(target_id: str, scan_type: str, run_id: str, step_name: str) -> str:
    db = SessionLocal()
    try:
        scan = Scan(
            id=str(uuid.uuid4()),
            target_id=target_id,
            scan_type=scan_type,
            module="pentest",
            status="pending",
            config_json=json.dumps({"playbook_run_id": run_id, "step": step_name}),
        )
        db.add(scan)
        db.commit()
        return scan.id
    finally:
        db.close()


def _update_run(run_id: str, **kwargs):
    db = SessionLocal()
    try:
        run = db.query(PlaybookRun).filter(PlaybookRun.id == run_id).first()
        if run:
            for k, v in kwargs.items():
                setattr(run, k, v)
            db.commit()
    finally:
        db.close()


def _finalize_scan(scan_id: str, scan_type: str, output: str) -> int:
    from services.output_parser import auto_parse_scan_output
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return 0
        scan.status = "completed"
        scan.raw_output = output
        scan.completed_at = datetime.utcnow()
        db.commit()
        parsed = auto_parse_scan_output(scan_type, output)
        for pf in parsed:
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
        db.commit()
        return len(parsed)
    finally:
        db.close()


async def _execute_step(
    scan_id: str,
    cmd: str,
    scan_type: str,
    timeout: int,
    send: SendFn,
    prefix_tool: Optional[str] = None,
) -> str:
    """Run a shell command, stream stdout, finalize scan record, return full output."""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "running"
            scan.started_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()

    chunks: list[str] = []
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            async for line in proc.stdout:  # type: ignore[union-attr]
                text = line.decode(errors="replace")
                chunks.append(text)
                if prefix_tool:
                    # Cyan tool label so parallel outputs stay identifiable
                    await send({"type": "stdout",
                                "data": f"\x1b[36m[{prefix_tool}]\x1b[0m {text}"})
                else:
                    await send({"type": "stdout", "data": text})
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await send({"type": "stdout", "data": "\n[⚠ timeout — step killed]\n"})
    except Exception as exc:
        await send({"type": "stdout", "data": f"\n[error: {exc}]\n"})
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = "failed"
                scan.completed_at = datetime.utcnow()
                db.commit()
        finally:
            db.close()
        return ""

    output = "".join(chunks)
    _finalize_scan(scan_id, scan_type, output)
    return output


# ── Per-step execution ─────────────────────────────────────────────────────────

async def _run_single_step(
    flat_idx: int,
    step: dict,
    target_host: str,
    real_target_id: str,
    run_id: str,
    nmap_snapshot: Optional[str],
    send: SendFn,
    prefix: bool = False,
) -> dict:
    """Execute one step and return a result dict.

    Result keys: idx, tool, output, findings, skipped, desc
    """
    tool = step["name"]
    scan_type = step.get("scan_type", tool)
    timeout = step.get("timeout", 300)
    step_desc = step.get("description", "")

    # Availability check
    if not shutil.which(tool):
        await send({"type": "step_skip",
                    "step": flat_idx, "tool": tool,
                    "status": "skipped", "reason": "not installed", "findings": 0})
        return {"idx": flat_idx, "tool": tool, "output": "",
                "findings": 0, "skipped": True, "desc": step_desc}

    # Conditional port check (uses nmap output from previous groups)
    if step.get("conditional") and step.get("trigger_ports"):
        if nmap_snapshot is None:
            await send({"type": "step_skip",
                        "step": flat_idx, "tool": tool,
                        "status": "skipped", "reason": "nmap not run yet", "findings": 0})
            return {"idx": flat_idx, "tool": tool, "output": "",
                    "findings": 0, "skipped": True, "desc": step_desc}
        open_ports = _extract_open_ports(nmap_snapshot)
        trigger = set(step["trigger_ports"])
        if not open_ports.intersection(trigger):
            reason = f"no trigger ports open ({', '.join(str(p) for p in sorted(trigger))})"
            await send({"type": "step_skip",
                        "step": flat_idx, "tool": tool,
                        "status": "skipped", "reason": reason, "findings": 0})
            return {"idx": flat_idx, "tool": tool, "output": "",
                    "findings": 0, "skipped": True, "desc": step_desc}

    cmd = step["cmd_template"].replace("{target}", target_host)
    scan_id = _create_scan(real_target_id, scan_type, run_id, tool)

    await send({
        "type": "step_start",
        "step": flat_idx, "tool": tool,
        "scan_id": scan_id, "cmd": cmd,
        "description": step_desc,
        "parallel": bool(step.get("parallel")),
    })

    output = await _execute_step(
        scan_id, cmd, scan_type, timeout, send,
        prefix_tool=tool if prefix else None,
    )

    db = SessionLocal()
    try:
        step_findings = db.query(Finding).filter(Finding.scan_id == scan_id).count()
    finally:
        db.close()

    await send({
        "type": "step_done",
        "step": flat_idx, "tool": tool,
        "status": "completed", "findings": step_findings,
    })

    return {"idx": flat_idx, "tool": tool, "output": output,
            "findings": step_findings, "skipped": False, "desc": step_desc}


# ── Main execution coroutine ───────────────────────────────────────────────────

async def execute_playbook_run(run_id: str, send: SendFn, use_ai: bool = False):
    """Drive a PlaybookRun to completion, streaming output via send().

    Steps are grouped into sequential slots.  Slots with more than one step
    run their steps concurrently via asyncio.gather.  Step-through mode
    pauses before each slot (not before each individual step).
    """
    db = SessionLocal()
    try:
        run = db.query(PlaybookRun).filter(PlaybookRun.id == run_id).first()
        if not run:
            await send({"type": "error", "data": "Run not found"})
            return
        from database import Playbook, Target
        playbook = db.query(Playbook).filter(Playbook.id == run.playbook_id).first()
        target = db.query(Target).filter(Target.id == run.target_id).first()
        if not playbook or not target:
            await send({"type": "error", "data": "Playbook or target not found"})
            return
        steps = json.loads(playbook.steps_json)
        target_host = target.hostname_or_ip
        mode = run.mode
        real_target_id = run.target_id
    finally:
        db.close()

    _update_run(run_id, status="running", started_at=datetime.utcnow())
    await send({"type": "run_start", "run_id": run_id, "total_steps": len(steps)})

    groups = _build_execution_groups(steps)

    # nmap_output accumulates across sequential groups for conditional checks
    nmap_output: Optional[str] = None
    total_findings = 0
    step_results: list[dict] = []

    for group_idx, group in enumerate(groups):
        is_parallel = len(group) > 1

        # ── Step-through pause (before each group after the first) ────────────
        if mode == "step_through" and group_idx > 0:
            first_flat_idx, first_step = group[0]
            group_step_info = [
                {"tool": s["name"], "description": s.get("description", "")}
                for _, s in group
            ]
            _update_run(run_id, status="paused",
                        current_step=str(first_flat_idx))
            await send({
                "type": "paused",
                "group": group_idx,
                "parallel": is_parallel,
                "group_steps": group_step_info,
                # Kept for backward compat with single-step pause UI
                "step": first_flat_idx,
                "tool": first_step["name"],
                "description": first_step.get("description", ""),
            })
            evt = get_continue_event(run_id)
            evt.clear()
            try:
                await asyncio.wait_for(evt.wait(), timeout=7200)
            except asyncio.TimeoutError:
                await send({"type": "error", "data": "Timed out waiting for continue"})
                _update_run(run_id, status="failed", completed_at=datetime.utcnow())
                return
            _update_run(run_id, status="running")

        # ── Execute the group ─────────────────────────────────────────────────
        if is_parallel:
            raw = await asyncio.gather(
                *[
                    _run_single_step(idx, step, target_host, real_target_id,
                                     run_id, nmap_output, send, prefix=True)
                    for idx, step in group
                ],
                return_exceptions=True,
            )
            results = [r for r in raw if isinstance(r, dict)]
        else:
            flat_idx, step = group[0]
            _update_run(run_id, current_step=str(flat_idx))
            result = await _run_single_step(
                flat_idx, step, target_host, real_target_id,
                run_id, nmap_output, send, prefix=False,
            )
            results = [result]

        # ── Process results ───────────────────────────────────────────────────
        for r in results:
            if not r.get("skipped"):
                total_findings += r["findings"]
                step_results.append({
                    "step": r["idx"], "tool": r["tool"],
                    "status": "completed", "findings": r["findings"],
                })
                # Accumulate nmap output for downstream conditional checks
                if r["tool"] == "nmap" and r["output"]:
                    nmap_output = (
                        (nmap_output + "\n" + r["output"]) if nmap_output else r["output"]
                    )
            else:
                step_results.append({
                    "step": r["idx"], "tool": r["tool"],
                    "status": "skipped", "findings": 0,
                })

        # ── AI analysis for the completed group ───────────────────────────────
        if use_ai:
            ai_coros = [
                _send_ai_insight(r["idx"], r["tool"], target_host,
                                  r.get("desc", ""), r["output"], send)
                for r in results
                if not r.get("skipped") and r.get("output")
            ]
            if mode == "step_through":
                # Await so insights arrive before the next group's pause
                await asyncio.gather(*ai_coros)
            else:
                for coro in ai_coros:
                    asyncio.create_task(coro)

    _update_run(run_id, status="completed", completed_at=datetime.utcnow(),
                results_json=json.dumps({"steps": step_results,
                                         "total_findings": total_findings}))
    await send({"type": "complete",
                "total_findings": total_findings, "steps": step_results})
    cleanup_run(run_id)
