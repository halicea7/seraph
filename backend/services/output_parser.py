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

        # Skip info lines
        if any(skip in line for skip in ["Target IP:", "Target Hostname:", "Target Port:", "Start Time:", "End Time:", "Nikto"]):
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

    if "lynis" in tool_name or "host_hardening" in scan_type_lower:
        return parse_lynis_output(raw_output)

    # Fallback: detect by output content — handles agent_audit with mixed tool output
    results: list[ParsedFinding] = []
    if "Nmap scan report" in raw_output or re.search(r"^\d+/(tcp|udp)\s+open", raw_output, re.MULTILINE):
        results.extend(parse_nmap_text(raw_output))
    if any(ln.strip().startswith("+ ") for ln in raw_output.splitlines()):
        results.extend(parse_nikto_output(raw_output))
    if "Suggestion [" in raw_output or "Warning [" in raw_output:
        results.extend(parse_lynis_output(raw_output))
    return results
