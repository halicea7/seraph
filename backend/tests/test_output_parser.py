"""Golden-file-style regression tests for services/output_parser.py's tool
parsers. Each test fixes a representative sample of real tool output and
asserts the exact parsed result, so a future change to the parsing logic
that silently drops or mis-categorizes a finding gets caught here instead
of only being noticed on a real scan.
"""
from services.output_parser import (
    parse_nmap_xml,
    parse_nmap_text,
    parse_nikto_output,
    parse_lynis_output,
    auto_parse_scan_output,
)

NMAP_XML_SAMPLE = """<?xml version="1.0"?>
<nmaprun>
<host>
<address addr="10.0.0.5" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="3.0.3"/></port>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9"/></port>
<port protocol="tcp" portid="23"><state state="closed"/><service name="telnet"/></port>
</ports>
</host>
</nmaprun>
"""


def test_parse_nmap_xml_flags_ftp_and_passes_through_ssh_as_info():
    findings = parse_nmap_xml(NMAP_XML_SAMPLE)
    titles = {f.title: f for f in findings}

    assert "FTP service exposed at 10.0.0.5:21" in titles
    ftp = titles["FTP service exposed at 10.0.0.5:21"]
    assert ftp.severity == "medium"
    assert "cleartext" in ftp.remediation.lower() or "sftp" in ftp.remediation.lower()

    # SSH has no notable-services entry -> falls through to the generic
    # info-level "open port" finding instead of being silently dropped.
    assert any(f.title == "Open port 22/tcp (ssh) on 10.0.0.5" and f.severity == "info" for f in findings)

    # A closed port must never produce a finding.
    assert not any("23" in f.title for f in findings)


def test_parse_nmap_xml_extracts_cve_and_cvss_from_nse_vuln_script():
    xml = """<?xml version="1.0"?>
<nmaprun>
<host>
<address addr="10.0.0.6" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="443">
  <state state="open"/>
  <service name="https"/>
  <script id="http-vuln-test" output="VULNERABLE: CVE-2014-0160 cvss: 7.5"/>
</port>
</ports>
</host>
</nmaprun>
"""
    findings = parse_nmap_xml(xml)
    # The NSE vuln-script finding and the generic "open port" info finding
    # both fire for the same port -- they aren't mutually exclusive.
    assert len(findings) == 2
    vuln = next(f for f in findings if f.cve_id)
    assert vuln.cve_id == "CVE-2014-0160"
    assert vuln.severity == "high"  # cvss 7.5 -> high, not critical (threshold is >= 9.0)


NMAP_TEXT_SAMPLE = """Nmap scan report for 10.0.0.7
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
80/tcp   open  http    Apache httpd 2.4.41
"""


def test_parse_nmap_text_matches_xml_parser_semantics():
    findings = parse_nmap_text(NMAP_TEXT_SAMPLE)
    titles = {f.title for f in findings}
    assert "FTP service exposed at 10.0.0.7:21" in titles
    assert "Open port 80/tcp (http) on 10.0.0.7" in titles


NIKTO_SAMPLE = """- Nikto v2.5.0
+ Target IP:          10.0.0.8
+ Target Hostname:    10.0.0.8
+ Target Port:        80
+ Start Time:         2024-01-01 00:00:00
+ Server: Apache/2.4.41
+ /admin/: Admin login page/section found.
+ The X-Content-Type-Options header is not set.
+ 7918 requests: 0 error(s) and 2 item(s) reported on remote host
+ End Time:           2024-01-01 00:05:00
"""


def test_parse_nikto_output_skips_banner_target_and_summary_lines():
    findings = parse_nikto_output(NIKTO_SAMPLE)
    titles = [f.title for f in findings]
    # Target/time/summary lines must be filtered out; a genuine "+" finding
    # line survives even when (like the server banner) it's low-value --
    # nikto's own output format doesn't distinguish those from the parser's
    # point of view.
    assert len(findings) == 3
    assert any("Admin login page" in t for t in titles)
    assert any("X-Content-Type-Options" in t for t in titles)
    assert not any("Target IP" in t or "Start Time" in t or "error(s) and" in t for t in titles)


# Note: the warning/suggestion regexes capture \w+ inside the brackets,
# which does not include a hyphen -- a bracketed test ID containing one
# (as real Lynis IDs like "AUTH-9262" do) would not match at all. That's
# pre-existing behavior this test isn't asserting on; AUTH9262/FIRE4590
# below avoid it to test the severity/control-mapping logic in isolation.
LYNIS_SAMPLE = """
Warning [AUTH9262]: SSH root login is enabled - [test:AUTH9262]
Suggestion [FIRE4590]: Consider hardening the firewall ruleset - [test:FIRE4590]
"""


def test_parse_lynis_output_maps_warning_and_suggestion_severities():
    findings = parse_lynis_output(LYNIS_SAMPLE)
    by_severity = {f.severity: f for f in findings}
    assert by_severity["high"].title.startswith("Lynis Warning [AUTH9262]")
    assert by_severity["low"].title.startswith("Lynis Suggestion [FIRE4590]")
    # "AUTH" prefix (first 4 chars of the test ID) maps to AC-2 in the
    # NIST-control lookup table, not the CM-6 generic-misconfiguration default.
    assert by_severity["high"].control_id == "AC-2"


def test_auto_parse_scan_output_dispatches_nmap_xml_by_content_not_just_scan_type():
    # scan_type doesn't mention nmap at all -- dispatch must still recognize
    # the <nmaprun> content and route to the XML parser.
    findings = auto_parse_scan_output("custom_tool", NMAP_XML_SAMPLE)
    assert any("FTP" in f.title for f in findings)


def test_auto_parse_scan_output_returns_empty_for_empty_input():
    assert auto_parse_scan_output("nmap", "") == []
