"""
Output parser service — converts raw scan output into structured Finding records.
Supports: Nmap XML, Nikto text output, Lynis log files.
"""

import xml.etree.ElementTree as ET
import re
import uuid
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class ParsedFinding:
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    control_id: Optional[str] = None
    framework: Optional[str] = None
    remediation: Optional[str] = None
    evidence: Optional[str] = None
    cve_id: Optional[str] = None
    extra_tags: list = field(default_factory=list)  # e.g. ["OWASP:A05:2021", "MITRE:T1046", "PCI:11"]


# ── Framework mapping tables ────────────────────────────────────────────────────

# OWASP Top 10 2021 tags by finding category
_OWASP = {
    "cleartext":    "OWASP:A02:2021",   # Cryptographic Failures
    "injection":    "OWASP:A03:2021",   # Injection
    "misconfiguration": "OWASP:A05:2021",  # Security Misconfiguration
    "outdated":     "OWASP:A06:2021",   # Vulnerable and Outdated Components
    "auth":         "OWASP:A07:2021",   # Authentication Failures
    "logging":      "OWASP:A09:2021",   # Logging Failures
    "access":       "OWASP:A01:2021",   # Broken Access Control
}

# MITRE ATT&CK technique tags by service/finding type
_MITRE = {
    "ftp":      ["MITRE:T1071.002", "MITRE:T1040"],   # FTP C2 + network sniffing
    "telnet":   ["MITRE:T1040", "MITRE:T1552"],        # Sniffing + unsecured creds
    "rsh":      ["MITRE:T1021", "MITRE:T1078"],
    "rlogin":   ["MITRE:T1021", "MITRE:T1078"],
    "rdp":      ["MITRE:T1021.001", "MITRE:T1133"],
    "smb":      ["MITRE:T1021.002"],
    "snmp":     ["MITRE:T1046", "MITRE:T1592"],
    "port":     ["MITRE:T1046"],                       # generic open port
    "vuln":     ["MITRE:T1190"],                       # exploit public-facing
    "web":      ["MITRE:T1190", "MITRE:T1071.001"],
    "auth":     ["MITRE:T1110", "MITRE:T1078"],
}

# PCI DSS requirement tags by category
_PCI = {
    "cleartext":    "PCI:4",    # Strong cryptography in transit
    "network":      "PCI:1",    # Network security controls
    "config":       "PCI:2",    # Secure configurations
    "vuln":         "PCI:6",    # Vulnerability management
    "vuln_scan":    "PCI:11",   # Security testing
    "auth":         "PCI:8",    # Authentication
    "logging":      "PCI:10",   # Logging and monitoring
    "access":       "PCI:7",    # Access control
}


def _severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    elif cvss >= 7.0:
        return "high"
    elif cvss >= 4.0:
        return "medium"
    elif cvss > 0:
        return "low"
    return "info"


def parse_nmap_xml(xml_content: str) -> list[ParsedFinding]:
    """Parse Nmap XML output into findings."""
    findings = []
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return findings

    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        host_addr = addr_el.attrib.get("addr", "unknown") if addr_el is not None else "unknown"

        ports_el = host.find("ports")
        if ports_el is None:
            continue

        for port in ports_el.findall("port"):
            protocol = port.attrib.get("protocol", "tcp")
            portid = port.attrib.get("portid", "?")
            state_el = port.find("state")
            state = state_el.attrib.get("state", "unknown") if state_el is not None else "unknown"
            if state != "open":
                continue

            service_el = port.find("service")
            service_name = ""
            service_version = ""
            if service_el is not None:
                service_name = service_el.attrib.get("name", "")
                product = service_el.attrib.get("product", "")
                version = service_el.attrib.get("version", "")
                service_version = f"{product} {version}".strip()

            # NSE script results — look for vulnerability findings
            for script in port.findall("script"):
                script_id = script.attrib.get("id", "")
                script_output = script.attrib.get("output", "")

                if any(keyword in script_id.lower() for keyword in ["vuln", "exploit", "cve"]):
                    # Try to extract CVE
                    cve_match = re.search(r"CVE-\d{4}-\d+", script_output, re.IGNORECASE)
                    cve = cve_match.group(0).upper() if cve_match else None

                    # Try to get CVSS score
                    cvss_match = re.search(r"cvss:\s*([\d.]+)", script_output, re.IGNORECASE)
                    cvss = float(cvss_match.group(1)) if cvss_match else 5.0
                    severity = _severity_from_cvss(cvss)

                    findings.append(ParsedFinding(
                        title=f"{script_id} on {host_addr}:{portid}/{protocol}",
                        description=f"NSE script '{script_id}' found potential vulnerability on {service_name} {service_version} at {host_addr}:{portid}",
                        severity=severity,
                        control_id="RA-5",
                        framework="NIST_800_53",
                        remediation="Apply vendor patches for identified vulnerabilities. Review service configurations.",
                        evidence=script_output[:1000],
                        cve_id=cve,
                        extra_tags=[_OWASP["outdated"], _MITRE["vuln"][0], _PCI["vuln_scan"]],
                    ))

            # Flag notable services — (label, severity, remediation, nist_ctrl, extra_tags)
            notable_services = {
                "ftp":          ("FTP service exposed",      "medium",   "FTP transmits credentials in cleartext. Replace with SFTP/SCP.",              "SI-2",  [_OWASP["cleartext"]] + _MITRE["ftp"]  + [_PCI["cleartext"]]),
                "telnet":       ("Telnet service exposed",   "high",     "Telnet transmits all data in cleartext. Replace with SSH.",                    "SC-8",  [_OWASP["cleartext"]] + _MITRE["telnet"] + [_PCI["cleartext"]]),
                "rsh":          ("rsh service exposed",      "critical", "rsh provides unauthenticated remote access. Disable immediately.",             "AC-17", [_OWASP["auth"]]      + _MITRE["rsh"]  + [_PCI["auth"]]),
                "rlogin":       ("rlogin service exposed",   "critical", "rlogin provides unauthenticated remote access. Disable immediately.",           "AC-17", [_OWASP["auth"]]      + _MITRE["rlogin"] + [_PCI["auth"]]),
                "smtp":         ("SMTP service exposed",     "low",      "Verify SMTP relay is restricted. Enable authentication.",                       "SC-8",  [_OWASP["misconfiguration"], _PCI["config"]]),
                "snmp":         ("SNMP service exposed",     "medium",   "Use SNMPv3 with authentication. Restrict to management networks.",              "SC-7",  [_OWASP["misconfiguration"]] + _MITRE["snmp"] + [_PCI["network"]]),
                "ms-wbt-server":("RDP exposed",              "medium",   "Restrict RDP access to VPN/jump hosts only.",                                  "AC-17", [_OWASP["access"]] + _MITRE["rdp"] + [_PCI["network"]]),
                "netbios-ssn":  ("NetBIOS/SMB exposed",      "medium",   "Restrict SMB access. Disable if not needed.",                                  "CM-7",  [_OWASP["access"]] + _MITRE["smb"] + [_PCI["network"]]),
            }
            if service_name.lower() in notable_services:
                label, sev, remediation, ctrl, extra_tags = notable_services[service_name.lower()]
                findings.append(ParsedFinding(
                    title=f"{label} at {host_addr}:{portid}",
                    description=f"Service '{service_name}' ({service_version}) detected on {host_addr}:{portid}/{protocol}",
                    severity=sev,
                    control_id=ctrl,
                    framework="NIST_800_53",
                    remediation=remediation,
                    evidence=f"Host: {host_addr} Port: {portid}/{protocol} Service: {service_name} {service_version}",
                    extra_tags=extra_tags,
                ))
            elif state == "open" and service_name:
                # Info-level finding for all open ports
                findings.append(ParsedFinding(
                    title=f"Open port {portid}/{protocol} ({service_name}) on {host_addr}",
                    description=f"Port {portid}/{protocol} is open running {service_name} {service_version}",
                    severity="info",
                    control_id="CM-8",
                    framework="NIST_800_53",
                    remediation="Verify this service is required. Close unnecessary ports.",
                    evidence=f"Host: {host_addr} Port: {portid}/{protocol} Service: {service_name} {service_version}",
                    extra_tags=_MITRE["port"] + [_PCI["vuln_scan"]],
                ))

    return findings


def parse_nikto_output(raw_output: str) -> list[ParsedFinding]:
    """Parse Nikto text output into findings."""
    findings = []
    lines = raw_output.splitlines()

    for line in lines:
        line = line.strip()
        if not line.startswith("+"):
            continue

        # Skip non-finding lines: headers, timeouts, and purely informational notices
        if any(skip in line for skip in [
            "Target IP:", "Target Hostname:", "Target Port:", "Start Time:", "End Time:",
            "Nikto",                                   # banner / version lines
            "No CGI Directories found",                # informational noise
            "0 error(s) and",                          # summary line
            "host(s) tested",                          # summary line
            "ERROR:",                                  # runtime errors (timeouts, connection refused, etc.)
            "end of test.",                            # end marker
            "No web server found",                     # connection failure
            "SSL connect failed",                      # TLS probe noise
            "0 item(s) reported",                      # empty result notice
        ]):
            continue

        # Determine severity from content keywords
        severity = "info"
        if any(kw in line.lower() for kw in ["vulnerable", "xss", "sql injection", "rce", "remote code", "exploit"]):
            severity = "high"
        elif any(kw in line.lower() for kw in ["outdated", "obsolete", "cve-", "default password", "weak"]):
            severity = "medium"
        elif any(kw in line.lower() for kw in ["header", "cookie", "config", "disclosure"]):
            severity = "low"

        # Extract CVE if present
        cve_match = re.search(r"CVE-\d{4}-\d+", line, re.IGNORECASE)
        cve = cve_match.group(0).upper() if cve_match else None

        # Build extra framework tags based on content
        extra_tags = list(_MITRE["web"])
        line_lower = line.lower()
        if any(k in line_lower for k in ["cve-", "outdated", "obsolete", "version"]):
            extra_tags += [_OWASP["outdated"], _PCI["vuln"]]
        elif any(k in line_lower for k in ["xss", "injection", "sql"]):
            extra_tags += [_OWASP["injection"], _PCI["vuln"]]
        elif any(k in line_lower for k in ["header", "cookie", "config", "disclosure"]):
            extra_tags += [_OWASP["misconfiguration"], _PCI["config"]]
        elif any(k in line_lower for k in ["auth", "password", "login"]):
            extra_tags += [_OWASP["auth"], _PCI["auth"]]
        else:
            extra_tags += [_OWASP["misconfiguration"], _PCI["vuln_scan"]]

        # Strip the leading "+ "
        description = line.lstrip("+ ").strip()
        title = description[:80] + ("..." if len(description) > 80 else "")

        findings.append(ParsedFinding(
            title=f"Nikto: {title}",
            description=description,
            severity=severity,
            control_id="RA-5",
            framework="NIST_800_53",
            remediation="Review and address the identified web server misconfiguration or vulnerability.",
            evidence=line,
            cve_id=cve,
            extra_tags=extra_tags,
        ))

    return findings


def parse_lynis_output(raw_output: str) -> list[ParsedFinding]:
    """Parse Lynis audit log output into findings."""
    findings = []
    lines = raw_output.splitlines()

    suggestion_pattern = re.compile(r"Suggestion\s*\[(\w+)\]:\s*(.+)")
    warning_pattern = re.compile(r"Warning\s*\[(\w+)\]:\s*(.+)")

    # LYNIS test ID → (NIST control, extra OWASP tag, PCI tag)
    test_mappings = {
        "AUTH": ("AC-2",  _OWASP["auth"],            _PCI["auth"]),
        "BOOT": ("CM-6",  _OWASP["misconfiguration"], _PCI["config"]),
        "CRYP": ("SC-8",  _OWASP["cleartext"],        _PCI["cleartext"]),
        "FILE": ("AU-9",  _OWASP["access"],            _PCI["access"]),
        "FIRE": ("SC-7",  _OWASP["misconfiguration"], _PCI["network"]),
        "KRNL": ("CM-6",  _OWASP["misconfiguration"], _PCI["config"]),
        "LOGG": ("AU-2",  _OWASP["logging"],           _PCI["logging"]),
        "NETW": ("SC-7",  _OWASP["misconfiguration"], _PCI["network"]),
        "PKGS": ("SI-2",  _OWASP["outdated"],          _PCI["vuln"]),
        "PRNT": ("CM-7",  _OWASP["misconfiguration"], _PCI["config"]),
        "PROC": ("CM-7",  _OWASP["misconfiguration"], _PCI["config"]),
        "SCHD": ("CM-7",  _OWASP["misconfiguration"], _PCI["config"]),
        "SSHD": ("AC-17", _OWASP["auth"],             _PCI["auth"]),
        "STRG": ("MP-2",  _OWASP["access"],            _PCI["access"]),
        "TIME": ("AU-8",  _OWASP["logging"],           _PCI["logging"]),
        "USB":  ("MP-7",  _OWASP["access"],            _PCI["access"]),
    }

    for line in lines:
        # Warnings → high severity
        w_match = warning_pattern.search(line)
        if w_match:
            test_id = w_match.group(1)
            message = w_match.group(2).strip()
            prefix = test_id[:4].upper()
            ctrl, owasp_tag, pci_tag = test_mappings.get(prefix, ("CM-6", _OWASP["misconfiguration"], _PCI["config"]))
            findings.append(ParsedFinding(
                title=f"Lynis Warning [{test_id}]: {message[:60]}",
                description=message,
                severity="high",
                control_id=ctrl,
                framework="NIST_800_53",
                remediation=f"Address Lynis warning {test_id}. Consult `lynis show details {test_id}` for guidance.",
                evidence=line.strip(),
                extra_tags=[owasp_tag, pci_tag],
            ))
            continue

        # Suggestions → low/medium severity
        s_match = suggestion_pattern.search(line)
        if s_match:
            test_id = s_match.group(1)
            message = s_match.group(2).strip()
            prefix = test_id[:4].upper()
            ctrl, owasp_tag, pci_tag = test_mappings.get(prefix, ("CM-6", _OWASP["misconfiguration"], _PCI["config"]))
            findings.append(ParsedFinding(
                title=f"Lynis Suggestion [{test_id}]: {message[:60]}",
                description=message,
                severity="low",
                control_id=ctrl,
                framework="NIST_800_53",
                remediation=f"Consider implementing: {message}. Run `lynis show details {test_id}` for details.",
                evidence=line.strip(),
                extra_tags=[owasp_tag, pci_tag],
            ))

    return findings


def parse_nmap_text(raw_output: str) -> list[ParsedFinding]:
    """Parse Nmap plain-text output (no -oX / -oA required)."""
    findings = []
    notable_services = {
        "ftp":          ("FTP service exposed",      "medium",   "FTP transmits credentials in cleartext. Replace with SFTP/SCP.",    "SI-2",  [_OWASP["cleartext"]] + _MITRE["ftp"]  + [_PCI["cleartext"]]),
        "telnet":       ("Telnet service exposed",   "high",     "Telnet transmits all data in cleartext. Replace with SSH.",          "SC-8",  [_OWASP["cleartext"]] + _MITRE["telnet"] + [_PCI["cleartext"]]),
        "rsh":          ("rsh service exposed",      "critical", "rsh provides unauthenticated remote access. Disable immediately.",   "AC-17", [_OWASP["auth"]] + _MITRE["rsh"] + [_PCI["auth"]]),
        "rlogin":       ("rlogin service exposed",   "critical", "rlogin provides unauthenticated remote access. Disable immediately.", "AC-17", [_OWASP["auth"]] + _MITRE["rlogin"] + [_PCI["auth"]]),
        "smtp":         ("SMTP service exposed",     "low",      "Verify SMTP relay is restricted. Enable authentication.",            "SC-8",  [_OWASP["misconfiguration"], _PCI["config"]]),
        "snmp":         ("SNMP service exposed",     "medium",   "Use SNMPv3 with authentication. Restrict to management networks.",   "SC-7",  [_OWASP["misconfiguration"]] + _MITRE["snmp"] + [_PCI["network"]]),
        "ms-wbt-server":("RDP exposed",              "medium",   "Restrict RDP access to VPN/jump hosts only.",                       "AC-17", [_OWASP["access"]] + _MITRE["rdp"] + [_PCI["network"]]),
        "netbios-ssn":  ("NetBIOS/SMB exposed",      "medium",   "Restrict SMB access. Disable if not needed.",                       "CM-7",  [_OWASP["access"]] + _MITRE["smb"] + [_PCI["network"]]),
        "microsoft-ds": ("SMB/CIFS exposed",         "medium",   "Restrict SMB access. Disable if not needed.",                       "CM-7",  [_OWASP["access"]] + _MITRE["smb"] + [_PCI["network"]]),
    }

    current_host = "unknown"
    # PORT   STATE  SERVICE  VERSION
    port_re = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)?$")

    for line in raw_output.splitlines():
        line = line.strip()

        # Track which host we're scanning
        m = re.match(r"Nmap scan report for (.+)", line)
        if m:
            current_host = m.group(1).strip()
            continue

        m = port_re.match(line)
        if not m:
            continue

        portid, protocol, service_name, version_str = m.groups()
        version_str = (version_str or "").strip()

        if service_name.lower() in notable_services:
            label, sev, remediation, ctrl, extra_tags = notable_services[service_name.lower()]
            findings.append(ParsedFinding(
                title=f"{label} at {current_host}:{portid}",
                description=f"Service '{service_name}' ({version_str}) detected on {current_host}:{portid}/{protocol}",
                severity=sev,
                control_id=ctrl,
                framework="NIST_800_53",
                remediation=remediation,
                evidence=f"Host: {current_host}  Port: {portid}/{protocol}  Service: {service_name}  Version: {version_str}",
                extra_tags=extra_tags,
            ))
        else:
            findings.append(ParsedFinding(
                title=f"Open port {portid}/{protocol} ({service_name}) on {current_host}",
                description=f"Port {portid}/{protocol} is open running {service_name} {version_str}",
                severity="info",
                control_id="CM-8",
                framework="NIST_800_53",
                remediation="Verify this service is required. Close unnecessary ports.",
                evidence=f"Host: {current_host}  Port: {portid}/{protocol}  Service: {service_name}  Version: {version_str}",
                extra_tags=_MITRE["port"] + [_PCI["vuln_scan"]],
            ))

    return findings


def parse_nuclei_output(raw_output: str) -> list[ParsedFinding]:
    """
    Parse Nuclei JSON-lines output (nuclei -json flag).
    Each line is a JSON object with fields: template-id, info.name, info.severity,
    info.description, matched-at, host, type, curl-command.
    """
    import json as _json
    findings: list[ParsedFinding] = []
    seen: set[str] = set()

    _sev_map = {
        "critical": "critical",
        "high":     "high",
        "medium":   "medium",
        "low":      "low",
        "info":     "info",
        "unknown":  "info",
    }

    for line in raw_output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = _json.loads(line)
        except Exception:
            continue

        info     = obj.get("info", {})
        name     = info.get("name") or obj.get("template-id", "Unknown")
        sev_raw  = info.get("severity", "info").lower()
        severity = _sev_map.get(sev_raw, "info")
        matched  = obj.get("matched-at") or obj.get("host", "")
        desc     = info.get("description", "")
        ref_list = info.get("reference", [])
        refs     = ", ".join(ref_list) if isinstance(ref_list, list) else str(ref_list)
        cve_id   = next((r for r in (ref_list if isinstance(ref_list, list) else []) if "CVE-" in r.upper()), None)
        if cve_id:
            import re as _re
            m = _re.search(r"CVE-\d{4}-\d+", cve_id, _re.IGNORECASE)
            cve_id = m.group(0).upper() if m else None

        key = f"{name}|{matched}"
        if key in seen:
            continue
        seen.add(key)

        findings.append(ParsedFinding(
            title=f"[Nuclei] {name}",
            description=f"{desc}\n\nMatched: {matched}" if desc else f"Matched: {matched}",
            severity=severity,
            remediation=f"Review: {refs}" if refs else "Review the Nuclei template documentation.",
            evidence=matched,
            cve_id=cve_id,
        ))

    return findings


def parse_feroxbuster_output(raw_output: str) -> list[ParsedFinding]:
    """
    Parse Feroxbuster output. Lines contain status code, size, words, lines, and URL.
    Example: 200      123l      456w     7890c http://target/admin
    We surface interesting status codes (200 for sensitive paths, 401/403 for protected resources).
    """
    import re as _re
    findings: list[ParsedFinding] = []
    seen: set[str] = set()

    # Match feroxbuster output lines: STATUS SIZE URL
    line_re = _re.compile(r"^(\d{3})\s+\S+\s+\S+\s+\S+\s+(https?://\S+)", _re.MULTILINE)

    _SENSITIVE = re.compile(
        r"/(admin|login|dashboard|config|backup|\.git|\.env|api|swagger|graphql|phpinfo|wp-admin|console|shell|upload|uploads|manager|panel|secret|token|key|passwd|password|shadow|database|db|sql|dump|install|setup|phpMyAdmin)",
        re.IGNORECASE,
    )

    for m in line_re.finditer(raw_output):
        status = int(m.group(1))
        url = m.group(2)

        if url in seen:
            continue
        seen.add(url)

        # 401/403 — protected resource found
        if status in (401, 403):
            findings.append(ParsedFinding(
                title=f"[Feroxbuster] Protected resource: {url}",
                description=f"HTTP {status} response at {url} — resource exists but access is restricted.",
                severity="low",
                remediation="Verify this resource should not be publicly accessible. Review authentication controls.",
                evidence=f"GET {url} → {status}",
            ))
        # 200 on a sensitive-looking path
        elif status == 200 and _SENSITIVE.search(url):
            findings.append(ParsedFinding(
                title=f"[Feroxbuster] Sensitive path accessible: {url}",
                description=f"HTTP 200 response at a potentially sensitive path: {url}",
                severity="medium",
                remediation="Verify this path should be publicly accessible. Restrict access if not required.",
                evidence=f"GET {url} → {status}",
            ))

    return findings


def parse_kerbrute_output(raw_output: str) -> list[ParsedFinding]:
    """
    Parse Kerbrute output.
    Valid users:  2024/01/01 00:00:00 >  [+] VALID USERNAME: jdoe@DOMAIN.LOCAL
    Valid creds:  2024/01/01 00:00:00 >  [+] VALID LOGIN: jdoe:Password1@DOMAIN.LOCAL
    """
    findings: list[ParsedFinding] = []

    user_re = re.compile(r"\[\+\]\s+VALID USERNAME:\s+(\S+)", re.IGNORECASE)
    cred_re = re.compile(r"\[\+\]\s+VALID LOGIN:\s+(\S+):(\S+)@(\S+)", re.IGNORECASE)

    valid_users: list[str] = []
    valid_creds: list[tuple[str, str, str]] = []

    for line in raw_output.splitlines():
        m = cred_re.search(line)
        if m:
            valid_creds.append((m.group(1), m.group(2), m.group(3)))
            continue
        m = user_re.search(line)
        if m:
            valid_users.append(m.group(1))

    if valid_users:
        findings.append(ParsedFinding(
            title=f"[Kerbrute] {len(valid_users)} valid Kerberos username(s) found",
            description=f"Valid AD usernames discovered via Kerberos pre-authentication probing:\n" + "\n".join(f"  • {u}" for u in valid_users),
            severity="medium",
            control_id="AC-2",
            framework="NIST_800_53",
            remediation="Restrict Kerberos pre-authentication enumeration. Implement account lockout and monitoring for repeated Kerberos AS-REQ failures.",
            evidence="\n".join(valid_users),
            extra_tags=["MITRE:T1087.002", "MITRE:T1558"],
        ))

    for username, password, domain in valid_creds:
        findings.append(ParsedFinding(
            title=f"[Kerbrute] Valid credential: {username}@{domain}",
            description=f"Kerberos password spray confirmed valid credential: {username}:{password} on {domain}",
            severity="critical",
            control_id="IA-5",
            framework="NIST_800_53",
            remediation="Immediately reset the compromised account password. Review password policy strength and enforce MFA.",
            evidence=f"{username}@{domain}",
            extra_tags=["MITRE:T1110.003", "MITRE:T1078.002"],
        ))

    return findings


def parse_nxc_output(raw_output: str) -> list[ParsedFinding]:
    """
    Parse NetExec (nxc) output.
    Pwn3d:   10.0.0.1:445 DOMAIN\\user (Pwn3d!)
    Shares:  10.0.0.1:445 DOMAIN\\user share READABLE
    NTDS:    DOMAIN\\user:500:aad3b...:ntlmhash:::
    """
    findings: list[ParsedFinding] = []

    pwn3d_re = re.compile(r"(\d+\.\d+\.\d+\.\d+).*\(Pwn3d!\)")
    share_re = re.compile(r"(\d+\.\d+\.\d+\.\d+).*\s(READ|WRITE)", re.IGNORECASE)
    ntds_re  = re.compile(r"^(.+\\\.+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::", re.MULTILINE)

    pwn3d_hosts: list[str] = []
    writable_shares: list[str] = []
    ntds_hashes: list[tuple[str, str]] = []

    for line in raw_output.splitlines():
        if pwn3d_re.search(line):
            m = pwn3d_re.search(line)
            if m:
                pwn3d_hosts.append(m.group(1))
        m = share_re.search(line)
        if m and "WRITE" in line.upper():
            writable_shares.append(line.strip())

    for m in ntds_re.finditer(raw_output):
        account = m.group(1)
        ntlm = m.group(4)
        ntds_hashes.append((account, ntlm))

    if pwn3d_hosts:
        findings.append(ParsedFinding(
            title=f"[NetExec] Admin access confirmed on {len(pwn3d_hosts)} host(s)",
            description=f"NetExec confirmed local/domain admin access (Pwn3d!) on:\n" + "\n".join(f"  • {h}" for h in pwn3d_hosts),
            severity="critical",
            control_id="AC-6",
            framework="NIST_800_53",
            remediation="Rotate all credentials used during testing. Review local admin group membership and disable NTLM where possible.",
            evidence="\n".join(pwn3d_hosts),
            extra_tags=["MITRE:T1021.002", "MITRE:T1078"],
        ))

    if writable_shares:
        findings.append(ParsedFinding(
            title=f"[NetExec] Writable SMB share(s) found",
            description=f"Write access to SMB shares discovered:\n" + "\n".join(f"  • {s}" for s in writable_shares[:20]),
            severity="high",
            control_id="CM-7",
            framework="NIST_800_53",
            remediation="Audit SMB share permissions. Remove unnecessary write access.",
            evidence="\n".join(writable_shares[:20]),
            extra_tags=["MITRE:T1021.002", "MITRE:T1083"],
        ))

    if ntds_hashes:
        findings.append(ParsedFinding(
            title=f"[NetExec] NTDS dump: {len(ntds_hashes)} NTLM hash(es) extracted",
            description=f"Domain credential hashes extracted from NTDS.dit. First 10 accounts:\n" + "\n".join(f"  • {a}" for a, _ in ntds_hashes[:10]),
            severity="critical",
            control_id="IA-5",
            framework="NIST_800_53",
            remediation="Rotate all domain account passwords. Force krbtgt double-reset. Implement tiered admin model.",
            evidence=f"{len(ntds_hashes)} NTLM hashes extracted",
            extra_tags=["MITRE:T1003.003", "MITRE:T1078.002"],
        ))

    return findings


def parse_secretsdump_output(raw_output: str) -> list[ParsedFinding]:
    """
    Parse impacket-secretsdump output.
    NTLM hashes: DOMAIN\\user:RID:LM:NTLM:::
    LSA secrets:  $MACHINE.ACC: ...
    Cached creds: DOMAIN/user:$DCC2$...
    """
    findings: list[ParsedFinding] = []

    # NTLM hash lines
    ntlm_re = re.compile(r"^(\S+\\[^:]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::", re.MULTILINE)
    ntlm_matches = ntlm_re.findall(raw_output)

    # LSA secrets
    lsa_re = re.compile(r"^\[(\*\].*LSA Secrets|\$MACHINE)", re.MULTILINE)
    has_lsa = bool(lsa_re.search(raw_output))

    # Cached domain creds (DCC2)
    dcc2_re = re.compile(r"\$DCC2\$", re.IGNORECASE)
    has_cached = bool(dcc2_re.search(raw_output))

    if ntlm_matches:
        accounts = [m[0] for m in ntlm_matches]
        findings.append(ParsedFinding(
            title=f"[secretsdump] {len(ntlm_matches)} NTLM hash(es) dumped",
            description=f"NTLM credential hashes extracted. Sample accounts:\n" + "\n".join(f"  • {a}" for a in accounts[:15]),
            severity="critical",
            control_id="IA-5",
            framework="NIST_800_53",
            remediation="Rotate all extracted account passwords immediately. Consider forest-wide password reset if domain admin hashes were obtained. Force krbtgt double-reset.",
            evidence=f"{len(ntlm_matches)} NTLM hashes — first: {accounts[0] if accounts else 'N/A'}",
            extra_tags=["MITRE:T1003.002", "MITRE:T1078.002"],
        ))

    if has_lsa:
        findings.append(ParsedFinding(
            title="[secretsdump] LSA secrets extracted",
            description="LSA secrets dumped from target. May contain service account credentials, machine account passwords, and cached domain credentials.",
            severity="critical",
            control_id="IA-5",
            framework="NIST_800_53",
            remediation="Rotate machine account passwords and any service accounts stored in LSA secrets.",
            evidence="LSA Secrets section found in secretsdump output",
            extra_tags=["MITRE:T1003.004", "MITRE:T1078"],
        ))

    if has_cached:
        findings.append(ParsedFinding(
            title="[secretsdump] Cached domain credentials (DCC2) found",
            description="Cached domain credential hashes (MS-Cache v2) found on target. Offline cracking may reveal domain passwords.",
            severity="high",
            control_id="IA-5",
            framework="NIST_800_53",
            remediation="Reduce CachedLogonsCount to 0 via Group Policy. Rotate credentials for affected accounts.",
            evidence="DCC2 hashes found in secretsdump output",
            extra_tags=["MITRE:T1003.005"],
        ))

    return findings


def parse_responder_output(raw_output: str) -> list[ParsedFinding]:
    """
    Parse Responder output for captured NTLMv2 hashes and poisoned requests.

    Example captured hash line:
      [SMB] NTLMv2-SSP Hash     : jdoe::CORP:4141414141414141:ABC123...:010100000...
    Example poisoned request:
      [*] [LLMNR]  Poisoned answer sent to 10.0.0.5 for name fileserver
    """
    findings: list[ParsedFinding] = []

    # NTLMv2 hash lines — format: username::domain:challenge:response:blob
    hash_re = re.compile(
        r"\[(?:SMB|HTTP|LDAP|MSSQL|FTP|SMTP|IMAP|POP3)\].*NTLMv2.*Hash\s*:\s*"
        r"(\S+)::(\S+):([0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+)",
        re.IGNORECASE,
    )
    # Poisoned answer lines
    poison_re = re.compile(
        r"\[\*\]\s+\[(LLMNR|NBT-NS|MDNS)\]\s+Poisoned answer sent to (\S+) for name (\S+)",
        re.IGNORECASE,
    )

    captured: dict[str, tuple[str, str, str]] = {}  # key → (user, domain, hash)
    poisoned: list[tuple[str, str, str]] = []        # (protocol, victim_ip, queried_name)

    for line in raw_output.splitlines():
        m = hash_re.search(line)
        if m:
            username, domain, hash_val = m.group(1), m.group(2), m.group(3)
            key = f"{username}@{domain}"
            if key not in captured:
                captured[key] = (username, domain, f"{username}::{domain}:{hash_val}")
            continue
        m = poison_re.search(line)
        if m:
            poisoned.append((m.group(1), m.group(2), m.group(3)))

    if captured:
        hash_list = [v[2] for v in captured.values()]
        account_list = list(captured.keys())
        findings.append(ParsedFinding(
            title=f"[Responder] {len(captured)} NTLMv2 hash(es) captured",
            description=(
                f"NTLMv2 challenge/response hashes captured via LLMNR/NBT-NS poisoning.\n"
                f"Accounts: {', '.join(account_list)}\n\n"
                f"Crack offline with: hashcat -m 5600 hashes.txt wordlist.txt"
            ),
            severity="critical",
            control_id="IA-5",
            framework="NIST_800_53",
            remediation=(
                "Disable LLMNR (Group Policy: Computer Config → Admin Templates → DNS Client → Turn off multicast name resolution).\n"
                "Disable NBT-NS via DHCP option 46 or adapter settings.\n"
                "Enable SMB signing to prevent relay attacks."
            ),
            evidence="\n".join(hash_list),
            extra_tags=["MITRE:T1557.001", "MITRE:T1040", "MITRE:T1187"],
        ))

    if poisoned and not captured:
        # Poisoning worked but no hashes yet — still noteworthy
        protocols = list({p[0] for p in poisoned})
        victims = list({p[1] for p in poisoned})
        findings.append(ParsedFinding(
            title=f"[Responder] Poisoning active — {len(poisoned)} broadcast(s) intercepted",
            description=(
                f"Responder successfully poisoned {', '.join(protocols)} broadcast queries from: {', '.join(victims[:10])}.\n"
                "No hashes captured yet — waiting for authentication attempts."
            ),
            severity="medium",
            control_id="SC-8",
            framework="NIST_800_53",
            remediation="Disable LLMNR and NBT-NS network-wide. Enable SMB signing.",
            evidence="\n".join(f"{p[0]} from {p[1]} → {p[2]}" for p in poisoned[:20]),
            extra_tags=["MITRE:T1557.001"],
        ))

    return findings


def parse_wafw00f_output(raw_output: str) -> list[ParsedFinding]:
    """
    Parse wafw00f output.

    Detected WAF:     [+] The site ... is behind Cloudflare (Cloudflare Inc.) WAF.
    Generic WAF:      [~] The site ... seems to be behind a WAF or some sort of security solution
    No WAF detected:  [~] The site ... does not seem to be behind a WAF
    """
    findings: list[ParsedFinding] = []

    # Named WAF detected
    waf_re = re.compile(r"\[\+\].*is behind (.+?) WAF", re.IGNORECASE)
    # Generic WAF signal
    generic_re = re.compile(r"seems to be behind a WAF", re.IGNORECASE)

    named_wafs: list[str] = []
    has_generic = False

    for line in raw_output.splitlines():
        m = waf_re.search(line)
        if m:
            named_wafs.append(m.group(1).strip())
            continue
        if generic_re.search(line):
            has_generic = True

    if named_wafs:
        waf_list = ", ".join(named_wafs)
        findings.append(ParsedFinding(
            title=f"[wafw00f] WAF detected: {waf_list}",
            description=(
                f"Web Application Firewall(s) detected in front of the target: {waf_list}.\n"
                "Active web scanning (nikto, nuclei, feroxbuster) may produce incomplete results "
                "or trigger WAF alerts. Consider using evasion techniques or passive recon."
            ),
            severity="info",
            control_id="SC-7",
            framework="NIST_800_53",
            remediation="WAF presence noted. Adjust scanning technique accordingly.",
            evidence=raw_output.strip()[:500],
            extra_tags=["MITRE:T1190", _OWASP["misconfiguration"]],
        ))
    elif has_generic:
        findings.append(ParsedFinding(
            title="[wafw00f] Possible WAF or security filter detected",
            description=(
                "wafw00f detected behaviour consistent with a WAF or security filter, "
                "but could not identify the vendor. Active scanning may be filtered."
            ),
            severity="info",
            control_id="SC-7",
            framework="NIST_800_53",
            remediation="WAF-like behaviour detected. Consider passive/slower scanning techniques.",
            evidence=raw_output.strip()[:500],
            extra_tags=[_OWASP["misconfiguration"]],
        ))

    return findings


def parse_testssl_output(raw_output: str) -> list[ParsedFinding]:
    """
    Parse testssl.sh plain-text output.

    testssl marks findings with severity words on the same line:
      VULNERABLE  — high (or critical if CVE score warrants)
      offered (NOT ok) / NOT ok — medium/high
      WEAK / weak — medium
      deprecated — low
    Lines containing "(OK)" or "not vulnerable" are skipped.
    """
    findings: list[ParsedFinding] = []

    # Map keyword → (severity, NIST control, OWASP tag, PCI tag)
    _sev_rules: list[tuple[str, str, str, str, str]] = [
        # (keyword-in-line, severity, nist, owasp, pci)
        ("VULNERABLE",           "high",   "SC-8",  _OWASP["cleartext"],        _PCI["vuln"]),
        ("NOT ok",               "medium", "SC-8",  _OWASP["misconfiguration"], _PCI["config"]),
        ("not ok",               "medium", "SC-8",  _OWASP["misconfiguration"], _PCI["config"]),
        ("WEAK",                 "medium", "SC-8",  _OWASP["cleartext"],        _PCI["cleartext"]),
        ("weak",                 "medium", "SC-8",  _OWASP["cleartext"],        _PCI["cleartext"]),
        ("deprecated",           "low",    "SC-8",  _OWASP["outdated"],         _PCI["vuln"]),
        ("offered (NOT ok)",     "medium", "SC-8",  _OWASP["misconfiguration"], _PCI["config"]),
        ("Certificate expired",  "high",   "IA-5",  _OWASP["misconfiguration"], _PCI["vuln"]),
        ("self-signed",          "medium", "IA-5",  _OWASP["misconfiguration"], _PCI["config"]),
    ]

    _skip = {"(OK)", "not vulnerable", "not offered", "default", "-- 0 units"}

    seen: set[str] = set()
    for line in raw_output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if any(s in stripped for s in _skip):
            continue

        matched_sev = None
        matched_nist = "SC-8"
        matched_owasp = _OWASP["misconfiguration"]
        matched_pci = _PCI["config"]
        for kw, sev, nist, owasp, pci in _sev_rules:
            if kw in stripped:
                matched_sev = sev
                matched_nist = nist
                matched_owasp = owasp
                matched_pci = pci
                break

        if not matched_sev:
            continue

        # Upgrade to critical if a CVE is mentioned
        cve_match = re.search(r"CVE-\d{4}-\d+", stripped, re.IGNORECASE)
        cve = cve_match.group(0).upper() if cve_match else None
        if matched_sev == "high" and cve:
            matched_sev = "critical"

        title = stripped[:100] + ("..." if len(stripped) > 100 else "")
        if title in seen:
            continue
        seen.add(title)

        findings.append(ParsedFinding(
            title=f"[testssl] {title}",
            description=stripped,
            severity=matched_sev,
            control_id=matched_nist,
            framework="NIST_800_53",
            remediation="Disable weak/deprecated TLS ciphers and protocols. Enforce TLS 1.2+ with strong cipher suites.",
            evidence=stripped,
            cve_id=cve,
            extra_tags=[matched_owasp, matched_pci, "MITRE:T1040"],
        ))

    return findings


def auto_parse_scan_output(scan_type: str, raw_output: str) -> list[ParsedFinding]:
    """Dispatch to the right parser based on scan type."""
    if not raw_output:
        return []

    scan_type_lower = scan_type.lower()
    # pentest scans use "engagement_type/phase/tool" — normalise to last segment
    tool_name = scan_type_lower.split("/")[-1]

    # Nmap — try XML first, fall back to text
    is_nmap = "nmap" in tool_name or "nmap" in scan_type_lower or "network_discovery" in scan_type_lower or "vulnerability_scan" in scan_type_lower
    if is_nmap or "<nmaprun" in raw_output:
        xml_start = raw_output.find("<?xml")
        if xml_start == -1:
            xml_start = raw_output.find("<nmaprun")
        if xml_start >= 0:
            return parse_nmap_xml(raw_output[xml_start:])
        # Plain-text nmap output
        if "Nmap scan report" in raw_output or "PORT" in raw_output:
            return parse_nmap_text(raw_output)

    if "nikto" in tool_name or "web_audit" in scan_type_lower:
        return parse_nikto_output(raw_output)

    if "nuclei" in tool_name:
        return parse_nuclei_output(raw_output)

    if "feroxbuster" in tool_name:
        return parse_feroxbuster_output(raw_output)

    if "kerbrute" in tool_name:
        return parse_kerbrute_output(raw_output)

    if "nxc" in tool_name or "netexec" in tool_name or "crackmapexec" in tool_name:
        return parse_nxc_output(raw_output)

    if "secretsdump" in tool_name:
        return parse_secretsdump_output(raw_output)

    if "responder" in tool_name:
        return parse_responder_output(raw_output)

    if "lynis" in tool_name or "host_hardening" in scan_type_lower:
        return parse_lynis_output(raw_output)

    if "testssl" in tool_name:
        return parse_testssl_output(raw_output)

    if "wafw00f" in tool_name:
        return parse_wafw00f_output(raw_output)

    # Fallback: detect by output content — handles agent_audit with mixed tool output
    results: list[ParsedFinding] = []
    if "Nmap scan report" in raw_output or re.search(r"^\d+/(tcp|udp)\s+open", raw_output, re.MULTILINE):
        results.extend(parse_nmap_text(raw_output))
    if any(ln.strip().startswith("+ ") for ln in raw_output.splitlines()):
        results.extend(parse_nikto_output(raw_output))
    if "Suggestion [" in raw_output or "Warning [" in raw_output:
        results.extend(parse_lynis_output(raw_output))
    if "VULNERABLE" in raw_output or "NOT ok" in raw_output:
        results.extend(parse_testssl_output(raw_output))
    return results
