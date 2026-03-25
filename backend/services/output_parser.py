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
                    cve_match = re.search(r"CVE-\d{4}-\d+", script_output)
                    cve = cve_match.group(0) if cve_match else None

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
                    ))

            # Flag notable services
            notable_services = {
                "ftp": ("FTP service exposed", "medium", "FTP transmits credentials in cleartext. Replace with SFTP/SCP.", "SI-2"),
                "telnet": ("Telnet service exposed", "high", "Telnet transmits all data in cleartext. Replace with SSH.", "SC-8"),
                "rsh": ("rsh service exposed", "critical", "rsh provides unauthenticated remote access. Disable immediately.", "AC-17"),
                "rlogin": ("rlogin service exposed", "critical", "rlogin provides unauthenticated remote access. Disable immediately.", "AC-17"),
                "smtp": ("SMTP service exposed", "low", "Verify SMTP relay is restricted. Enable authentication.", "SC-8"),
                "snmp": ("SNMP service exposed", "medium", "Use SNMPv3 with authentication. Restrict to management networks.", "SC-7"),
                "ms-wbt-server": ("RDP exposed", "medium", "Restrict RDP access to VPN/jump hosts only.", "AC-17"),
                "netbios-ssn": ("NetBIOS/SMB exposed", "medium", "Restrict SMB access. Disable if not needed.", "CM-7"),
            }
            if service_name.lower() in notable_services:
                label, sev, remediation, ctrl = notable_services[service_name.lower()]
                findings.append(ParsedFinding(
                    title=f"{label} at {host_addr}:{portid}",
                    description=f"Service '{service_name}' ({service_version}) detected on {host_addr}:{portid}/{protocol}",
                    severity=sev,
                    control_id=ctrl,
                    framework="NIST_800_53",
                    remediation=remediation,
                    evidence=f"Host: {host_addr} Port: {portid}/{protocol} Service: {service_name} {service_version}",
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
        cve_match = re.search(r"CVE-\d{4}-\d+", line)
        ctrl = "RA-5"
        framework = "NIST_800_53"

        # Strip the leading "+ "
        description = line.lstrip("+ ").strip()
        title = description[:80] + ("..." if len(description) > 80 else "")

        findings.append(ParsedFinding(
            title=f"Nikto: {title}",
            description=description,
            severity=severity,
            control_id=ctrl,
            framework=framework,
            remediation="Review and address the identified web server misconfiguration or vulnerability.",
            evidence=line,
        ))

    return findings


def parse_lynis_output(raw_output: str) -> list[ParsedFinding]:
    """Parse Lynis audit log output into findings."""
    findings = []
    lines = raw_output.splitlines()

    suggestion_pattern = re.compile(r"Suggestion\s*\[(\w+)\]:\s*(.+)")
    warning_pattern = re.compile(r"Warning\s*\[(\w+)\]:\s*(.+)")

    # LYNIS test ID to CIS/NIST mapping (partial)
    test_mappings = {
        "AUTH": ("AC-2", "NIST_800_53"),
        "BOOT": ("CM-6", "NIST_800_53"),
        "CRYP": ("SC-8", "NIST_800_53"),
        "FILE": ("AU-9", "NIST_800_53"),
        "FIRE": ("SC-7", "NIST_800_53"),
        "KRNL": ("CM-6", "NIST_800_53"),
        "LOGG": ("AU-2", "NIST_800_53"),
        "NETW": ("SC-7", "NIST_800_53"),
        "PKGS": ("SI-2", "NIST_800_53"),
        "PRNT": ("CM-7", "NIST_800_53"),
        "PROC": ("CM-7", "NIST_800_53"),
        "SCHD": ("CM-7", "NIST_800_53"),
        "SSHD": ("AC-17", "NIST_800_53"),
        "STRG": ("MP-2", "NIST_800_53"),
        "TIME": ("AU-8", "NIST_800_53"),
        "USB": ("MP-7", "NIST_800_53"),
    }

    for line in lines:
        # Warnings → high severity
        w_match = warning_pattern.search(line)
        if w_match:
            test_id = w_match.group(1)
            message = w_match.group(2).strip()
            prefix = test_id[:4].upper()
            ctrl, framework = test_mappings.get(prefix, ("CM-6", "NIST_800_53"))
            findings.append(ParsedFinding(
                title=f"Lynis Warning [{test_id}]: {message[:60]}",
                description=message,
                severity="high",
                control_id=ctrl,
                framework=framework,
                remediation=f"Address Lynis warning {test_id}. Consult `lynis show details {test_id}` for guidance.",
                evidence=line.strip(),
            ))
            continue

        # Suggestions → low/medium severity
        s_match = suggestion_pattern.search(line)
        if s_match:
            test_id = s_match.group(1)
            message = s_match.group(2).strip()
            prefix = test_id[:4].upper()
            ctrl, framework = test_mappings.get(prefix, ("CM-6", "NIST_800_53"))
            findings.append(ParsedFinding(
                title=f"Lynis Suggestion [{test_id}]: {message[:60]}",
                description=message,
                severity="low",
                control_id=ctrl,
                framework=framework,
                remediation=f"Consider implementing: {message}. Run `lynis show details {test_id}` for details.",
                evidence=line.strip(),
            ))

    return findings


def parse_nmap_text(raw_output: str) -> list[ParsedFinding]:
    """Parse Nmap plain-text output (no -oX / -oA required)."""
    findings = []
    notable_services = {
        "ftp": ("FTP service exposed", "medium", "FTP transmits credentials in cleartext. Replace with SFTP/SCP.", "SI-2"),
        "telnet": ("Telnet service exposed", "high", "Telnet transmits all data in cleartext. Replace with SSH.", "SC-8"),
        "rsh": ("rsh service exposed", "critical", "rsh provides unauthenticated remote access. Disable immediately.", "AC-17"),
        "rlogin": ("rlogin service exposed", "critical", "rlogin provides unauthenticated remote access. Disable immediately.", "AC-17"),
        "smtp": ("SMTP service exposed", "low", "Verify SMTP relay is restricted. Enable authentication.", "SC-8"),
        "snmp": ("SNMP service exposed", "medium", "Use SNMPv3 with authentication. Restrict to management networks.", "SC-7"),
        "ms-wbt-server": ("RDP exposed", "medium", "Restrict RDP access to VPN/jump hosts only.", "AC-17"),
        "netbios-ssn": ("NetBIOS/SMB exposed", "medium", "Restrict SMB access. Disable if not needed.", "CM-7"),
        "microsoft-ds": ("SMB/CIFS exposed", "medium", "Restrict SMB access. Disable if not needed.", "CM-7"),
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
            label, sev, remediation, ctrl = notable_services[service_name.lower()]
            findings.append(ParsedFinding(
                title=f"{label} at {current_host}:{portid}",
                description=f"Service '{service_name}' ({version_str}) detected on {current_host}:{portid}/{protocol}",
                severity=sev,
                control_id=ctrl,
                framework="NIST_800_53",
                remediation=remediation,
                evidence=f"Host: {current_host}  Port: {portid}/{protocol}  Service: {service_name}  Version: {version_str}",
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
