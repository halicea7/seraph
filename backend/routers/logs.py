from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
import re

from database import get_db, AppSetting
from services.ai_client import chat_complete, load_llm_params

router = APIRouter(prefix="/logs", tags=["logs"])

# ── IOC extraction patterns ──────────────────────────────────────────────────

_IP = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_DOMAIN = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|gov|edu|mil|info|biz|xyz|top|online|site|[a-z]{2})\b',
    re.I,
)
_MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
_SHA1 = re.compile(r'\b[a-fA-F0-9]{40}\b')
_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
_EMAIL = re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b')
_URL = re.compile(r'https?://[^\s<>"\']+')
_PRIVATE_IP = re.compile(
    r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.)'
)

# ── Attack pattern detection rules ──────────────────────────────────────────

PATTERNS = [
    {
        "id": "ssh_bruteforce",
        "name": "SSH Brute Force",
        "severity": "high",
        "regex": re.compile(r'(Failed password|authentication failure|Invalid user).{0,30}(ssh|sshd)', re.I),
        "description": "Multiple SSH authentication failures — possible brute force attack.",
    },
    {
        "id": "sudo_escalation",
        "name": "Privilege Escalation (sudo)",
        "severity": "medium",
        "regex": re.compile(r'sudo.*COMMAND|sudo.*session opened for user root', re.I),
        "description": "Sudo execution to root detected — verify this was authorized.",
    },
    {
        "id": "reverse_shell",
        "name": "Reverse Shell Indicator",
        "severity": "critical",
        "regex": re.compile(
            r'(nc|ncat|netcat|bash -i|sh -i|python.*pty|socat).{0,40}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\bLISTEN\b)',
            re.I,
        ),
        "description": "Potential reverse shell command detected.",
    },
    {
        "id": "remote_download",
        "name": "Remote File Download",
        "severity": "high",
        "regex": re.compile(r'(wget|curl)\s+https?://', re.I),
        "description": "Remote file download command — possible payload delivery.",
    },
    {
        "id": "credential_file_access",
        "name": "Credential File Access",
        "severity": "critical",
        "regex": re.compile(r'(cat|more|less|head|tail|vi|nano|type)\s+.*(etc/passwd|etc/shadow|etc/sudoers|SAM\b|NTDS\.dit)', re.I),
        "description": "Direct access to credential files detected.",
    },
    {
        "id": "tmp_execution",
        "name": "Execution from /tmp or /dev/shm",
        "severity": "high",
        "regex": re.compile(r'(/tmp/|/dev/shm/)\S+\s', re.I),
        "description": "Binary execution from temporary directory — common malware staging.",
    },
    {
        "id": "cron_modification",
        "name": "Cron Job Modification",
        "severity": "medium",
        "regex": re.compile(r'(crontab|cron\.d|cron\.daily|cron\.hourly|at\.allow)', re.I),
        "description": "Cron/scheduled task modification — possible persistence mechanism.",
    },
    {
        "id": "new_user_account",
        "name": "New User Account Created",
        "severity": "high",
        "regex": re.compile(r'(useradd|adduser|net user\s+\S+\s+/add)', re.I),
        "description": "New user account creation — possible backdoor account.",
    },
    {
        "id": "port_scan_tool",
        "name": "Port Scanning Tool",
        "severity": "medium",
        "regex": re.compile(r'\b(nmap|masscan|rustscan|zmap|unicornscan|arp-scan)\b', re.I),
        "description": "Port scanning tool usage detected.",
    },
    {
        "id": "sql_injection",
        "name": "SQL Injection Attempt",
        "severity": "high",
        "regex": re.compile(
            r"(UNION\s+SELECT|OR\s+1\s*=\s*1|'\s*OR\s*'|DROP\s+TABLE|xp_cmdshell|EXEC\s+\(|WAITFOR\s+DELAY)",
            re.I,
        ),
        "description": "SQL injection patterns in log data.",
    },
    {
        "id": "log_clearing",
        "name": "Log Clearing / Anti-Forensics",
        "severity": "critical",
        "regex": re.compile(
            r'(>\s*/var/log|truncate.*\.log|rm\s+.*\.log|wevtutil.*clear|auditctl.*stop|shred.*log)',
            re.I,
        ),
        "description": "Log clearing activity detected — active anti-forensics indicator.",
    },
    {
        "id": "xss_attempt",
        "name": "XSS Attempt",
        "severity": "medium",
        "regex": re.compile(r'(<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie)', re.I),
        "description": "Cross-site scripting (XSS) pattern in web log.",
    },
    {
        "id": "path_traversal",
        "name": "Path Traversal Attempt",
        "severity": "high",
        "regex": re.compile(r'(\.\./\.\.|%2e%2e|%252e%252e|\.\.%2f|\.\.%5c)', re.I),
        "description": "Directory traversal attempt detected in web requests.",
    },
    {
        "id": "shell_upload",
        "name": "Webshell Upload",
        "severity": "critical",
        "regex": re.compile(r'\.(php|asp|aspx|jsp|cgi)\s*(POST|PUT)|\beval\s*\(|\bbase64_decode\s*\(', re.I),
        "description": "Possible webshell upload or server-side code injection.",
    },
]


def _extract_iocs(text: str) -> dict:
    ips = set(_IP.findall(text))
    public_ips = sorted(ip for ip in ips if not _PRIVATE_IP.match(ip))
    private_ips = sorted(ip for ip in ips if _PRIVATE_IP.match(ip))

    domains = {d.lower() for d in _DOMAIN.findall(text)}
    # Remove log-file-like false positives
    domains = {d for d in domains if not any(d.endswith(x) for x in ('.log', '.txt', '.conf', '.sh', '.py', '.yml'))}

    # Extract hashes longest-first to avoid sub-match collisions
    sha256 = set(_SHA256.findall(text))
    scrubbed = text
    for h in sha256:
        scrubbed = scrubbed.replace(h, ' ')
    sha1 = set(_SHA1.findall(scrubbed))
    for h in sha1:
        scrubbed = scrubbed.replace(h, ' ')
    md5 = set(_MD5.findall(scrubbed))

    return {
        "public_ips": public_ips[:50],
        "private_ips": private_ips[:50],
        "domains": sorted(domains)[:50],
        "md5": sorted(md5)[:20],
        "sha1": sorted(sha1)[:20],
        "sha256": sorted(sha256)[:20],
        "emails": sorted(set(_EMAIL.findall(text)))[:20],
        "urls": sorted(set(_URL.findall(text)))[:30],
    }


def _match_patterns(text: str) -> list:
    lines = text.splitlines()
    hits: dict[str, dict] = {}

    for i, line in enumerate(lines):
        for pattern in PATTERNS:
            if pattern["regex"].search(line):
                pid = pattern["id"]
                if pid not in hits:
                    hits[pid] = {
                        "id": pid,
                        "name": pattern["name"],
                        "severity": pattern["severity"],
                        "description": pattern["description"],
                        "matches": [],
                    }
                if len(hits[pid]["matches"]) < 5:
                    hits[pid]["matches"].append({
                        "line": i + 1,
                        "text": line.strip()[:200],
                    })

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(hits.values(), key=lambda x: sev_order.get(x["severity"], 9))


# ── Endpoints ────────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    text: str
    project_id: Optional[str] = None


class AITriageRequest(BaseModel):
    text: str
    patterns: list[dict] = []


@router.post("/analyze")
def analyze_log(req: AnalyzeRequest):
    if len(req.text) > 500_000:
        raise HTTPException(400, "Log text too large (max 500 KB)")

    patterns = _match_patterns(req.text)
    iocs = _extract_iocs(req.text)
    line_count = req.text.count('\n') + 1
    ioc_count = sum(len(v) for v in iocs.values() if isinstance(v, list))

    return {
        "line_count": line_count,
        "patterns": patterns,
        "iocs": iocs,
        "pattern_count": len(patterns),
        "ioc_count": ioc_count,
    }


@router.post("/ai-triage")
def ai_triage(req: AITriageRequest, db: Session = Depends(get_db)):
    def _get(key: str, default: str = "") -> str:
        row = db.query(AppSetting).filter(AppSetting.key == key).first()
        return row.value if row else default

    endpoint = _get("ai_endpoint", "http://localhost:11434")
    model = _get("ai_model", "")
    if not model:
        raise HTTPException(400, "No AI model configured. Go to Settings → AI to set one.")

    log_excerpt = req.text[:4000]
    patterns_summary = "\n".join(
        f"- [{p['severity'].upper()}] {p['name']}: {p['description']}"
        for p in req.patterns[:10]
    ) or "None detected by automated rules."

    prompt = (
        f"You are a threat analyst performing log triage.\n\n"
        f"Automated detection flagged these patterns:\n{patterns_summary}\n\n"
        f"Log excerpt:\n```\n{log_excerpt}\n```\n\n"
        f"Provide:\n"
        f"1. Overall threat assessment (severity and confidence)\n"
        f"2. What likely happened (attack chain or benign explanation)\n"
        f"3. Most critical indicators to investigate further\n"
        f"4. Immediate containment recommendations\n"
        f"Be concise and actionable."
    )

    try:
        result = chat_complete(endpoint, model, [{"role": "user", "content": prompt}], **load_llm_params(db))
        return {"triage": result}
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))
