from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import uuid

from database import get_db, AppSetting, Project, Target, Scan, Finding, VulnerabilityRecord, Credential

router = APIRouter(prefix="/demo", tags=["demo"])

DEMO_MARKER = "__seraph_demo__"


def _get(db: Session, key: str, default: str = "") -> str:
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    return row.value if row else default


def _set(db: Session, key: str, value: str) -> None:
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(AppSetting(key=key, value=value))


# ── Status ────────────────────────────────────────────────────────────────────

@router.get("/status")
def demo_status(db: Session = Depends(get_db)):
    return {"active": _get(db, "demo_mode", "false") == "true"}


# ── Seed ──────────────────────────────────────────────────────────────────────

@router.post("/seed")
def seed_demo(db: Session = Depends(get_db)):
    # Guard against double-seeding
    if db.query(Project).filter(Project.description == DEMO_MARKER).first():
        _set(db, "demo_mode", "true")
        db.commit()
        return {"ok": True}

    now = datetime.utcnow()

    def pid() -> str:
        return str(uuid.uuid4())

    # ── Project 1: External Pentest ───────────────────────────────────────────
    p1_id = pid()
    db.add(Project(id=p1_id, name="Acme Corp — External Pentest",
                   description=DEMO_MARKER, created_at=now - timedelta(days=14)))

    ta_id, tb_id = pid(), pid()
    db.add(Target(id=ta_id, project_id=p1_id, hostname_or_ip="203.0.113.10",
                  target_type="linux_host", ports="22,80,443,8080",
                  notes="Primary web server", created_at=now - timedelta(days=14)))
    db.add(Target(id=tb_id, project_id=p1_id, hostname_or_ip="203.0.113.50",
                  target_type="windows_host", ports="445,3389,5985",
                  notes="Jump host", created_at=now - timedelta(days=14)))

    sa_id = pid()
    db.add(Scan(id=sa_id, target_id=ta_id, scan_type="network_discovery,vulnerability_scan",
                module="pentest", status="completed", config_json="{}",
                created_at=now - timedelta(days=13), started_at=now - timedelta(days=13),
                completed_at=now - timedelta(days=13) + timedelta(hours=2)))

    for sev, title, desc, cve, cvss in [
        ("critical",
         "Remote Code Execution via Log4Shell",
         "The application uses a vulnerable Log4j version. An unauthenticated attacker can execute "
         "arbitrary code via JNDI injection in HTTP headers.",
         "CVE-2021-44228", "10.0"),
        ("high",
         "SQL Injection in /api/login Endpoint",
         "The username parameter is not sanitised, allowing authentication bypass and full database "
         "extraction via UNION-based SQL injection.",
         None, None),
        ("high",
         "Unauthenticated Admin Panel on Port 8080",
         "An administrative interface is accessible with default credentials (admin / admin).",
         None, None),
        ("medium",
         "Outdated OpenSSL 1.0.2 (End-of-Life)",
         "OpenSSL 1.0.2 has reached end-of-life. Several high-severity CVEs affect this version.",
         "CVE-2022-0778", "7.5"),
        ("low",
         "Directory Listing Enabled on Web Root",
         "Apache directory listing exposes the full file-system tree to unauthenticated visitors.",
         None, None),
        ("info",
         "Web Server Banner Disclosure",
         "The Server response header reveals Apache/2.4.41 Ubuntu, aiding attacker fingerprinting.",
         None, None),
    ]:
        db.add(Finding(id=pid(), scan_id=sa_id, severity=sev, title=title,
                       description=desc, cve_id=cve, cvss_score=cvss,
                       created_at=now - timedelta(days=13)))

    sb_id = pid()
    db.add(Scan(id=sb_id, target_id=tb_id, scan_type="network_discovery",
                module="pentest", status="completed", config_json="{}",
                created_at=now - timedelta(days=12), started_at=now - timedelta(days=12),
                completed_at=now - timedelta(days=12) + timedelta(hours=1)))

    for sev, title, desc, cve, cvss in [
        ("critical",
         "MS17-010 EternalBlue — Unauthenticated RCE",
         "The Windows host has not applied MS17-010. Full SYSTEM-level code execution is possible "
         "without credentials, as demonstrated by WannaCry and NotPetya.",
         "CVE-2017-0144", "9.8"),
        ("high",
         "SMB Signing Not Required",
         "SMB signing is disabled, making the host susceptible to NTLM relay attacks.",
         None, None),
        ("medium",
         "RDP Accessible from Internet (Port 3389)",
         "Remote Desktop is reachable from the public internet with no network-level restriction.",
         None, None),
    ]:
        db.add(Finding(id=pid(), scan_id=sb_id, severity=sev, title=title,
                       description=desc, cve_id=cve, cvss_score=cvss,
                       created_at=now - timedelta(days=12)))

    for username, secret, ctype, host, notes in [
        ("admin",      "admin123!",                    "password", "203.0.113.10", "Admin panel — default creds"),
        ("root",       "$6$rounds=5000$saltsalt$hash", "hash",     "203.0.113.10", "Extracted from /etc/shadow"),
        ("svc_backup", "Backup2024@corp",              "password", "203.0.113.50", "Found in plaintext config"),
    ]:
        db.add(Credential(id=pid(), project_id=p1_id, username=username, secret=secret,
                          cred_type=ctype, source="post_exploitation", target_host=host,
                          notes=notes, created_at=now - timedelta(days=12)))

    for title, sev, cve, cvss, asset, status in [
        ("Remote Code Execution via Log4Shell",       "critical", "CVE-2021-44228", "10.0", "203.0.113.10", "in_progress"),
        ("MS17-010 EternalBlue — Unauthenticated RCE","critical", "CVE-2017-0144",  "9.8",  "203.0.113.50", "open"),
        ("SQL Injection in /api/login Endpoint",       "high",     None,             None,   "203.0.113.10", "open"),
        ("Unauthenticated Admin Panel on Port 8080",   "high",     None,             None,   "203.0.113.10", "mitigated"),
    ]:
        db.add(VulnerabilityRecord(id=pid(), project_id=p1_id, title=title,
                                   severity=sev, status=status, cve_id=cve,
                                   cvss_score=cvss, affected_asset=asset,
                                   created_at=now - timedelta(days=12)))

    # ── Project 2: Web App Audit ──────────────────────────────────────────────
    p2_id = pid()
    db.add(Project(id=p2_id, name="Beta Systems — Web Application Audit",
                   description=DEMO_MARKER, created_at=now - timedelta(days=7)))

    tc_id = pid()
    db.add(Target(id=tc_id, project_id=p2_id, hostname_or_ip="app.beta-systems.local",
                  target_type="web_app", ports="80,443",
                  notes="Customer portal", created_at=now - timedelta(days=7)))

    sc_id = pid()
    db.add(Scan(id=sc_id, target_id=tc_id, scan_type="web_audit,vulnerability_scan",
                module="audit", status="completed", config_json="{}",
                created_at=now - timedelta(days=6), started_at=now - timedelta(days=6),
                completed_at=now - timedelta(days=6) + timedelta(hours=3)))

    for sev, title, desc in [
        ("high",   "Missing Content Security Policy",
         "No CSP header is set, leaving the application exposed to XSS and data-injection attacks."),
        ("high",   "Stored XSS in Profile Comments Field",
         "User input in the profile comments field is rendered without encoding, enabling persistent XSS."),
        ("medium", "Session Cookies Missing Secure and HttpOnly Flags",
         "Session tokens can be stolen via XSS or transmitted over HTTP."),
        ("medium", "Weak Password Policy — 6 Character Minimum",
         "No complexity requirements and a 6-character minimum allow trivially guessable passwords."),
        ("low",    "Verbose Error Messages Expose Stack Traces",
         "Unhandled exceptions return full Python tracebacks including file paths and library versions."),
        ("info",   "Outdated Framework — Django 3.2 (LTS Expired)",
         "Django 3.2 LTS reached end-of-life April 2024."),
    ]:
        db.add(Finding(id=pid(), scan_id=sc_id, severity=sev, title=title,
                       description=desc, created_at=now - timedelta(days=6)))

    db.add(Credential(id=pid(), project_id=p2_id, username="testuser@beta.com",
                      secret="Password1", cred_type="password", source="brute_force",
                      target_host="app.beta-systems.local", notes="Default test account",
                      created_at=now - timedelta(days=5)))

    for title, sev, asset, status in [
        ("Missing Content Security Policy",       "high",   "app.beta-systems.local", "open"),
        ("Stored XSS in Profile Comments Field",  "high",   "app.beta-systems.local", "in_progress"),
        ("Session Cookies Missing Flags",          "medium", "app.beta-systems.local", "open"),
    ]:
        db.add(VulnerabilityRecord(id=pid(), project_id=p2_id, title=title,
                                   severity=sev, status=status, affected_asset=asset,
                                   created_at=now - timedelta(days=6)))

    # ── Project 3: Internal Assessment ───────────────────────────────────────
    p3_id = pid()
    db.add(Project(id=p3_id, name="Q1 2025 — Internal Network Assessment",
                   description=DEMO_MARKER, created_at=now - timedelta(days=3)))

    td_id = pid()
    db.add(Target(id=td_id, project_id=p3_id, hostname_or_ip="10.0.0.0/24",
                  target_type="network", notes="Corporate LAN segment",
                  created_at=now - timedelta(days=3)))

    sd_id = pid()
    db.add(Scan(id=sd_id, target_id=td_id, scan_type="host_hardening,network_discovery",
                module="audit", status="completed", config_json="{}",
                created_at=now - timedelta(days=2), started_at=now - timedelta(days=2),
                completed_at=now - timedelta(days=2) + timedelta(hours=4)))

    for sev, title, desc in [
        ("high",   "Default Credentials on Core Network Switches",
         "All core switches use factory-default credentials (admin / cisco)."),
        ("high",   "Telnet Enabled on Network Devices",
         "Telnet (port 23) is active on 8 devices, transmitting credentials in plaintext."),
        ("medium", "SNMP v1/v2c with Community String 'public'",
         "Unauthenticated read access to full device configuration via SNMP."),
        ("medium", "SSH Protocol Version 1 Accepted",
         "SSHv1 is cryptographically broken. 4 hosts still accept it."),
        ("low",    "NFS Shares World-Readable",
         "Two NFS exports have no host restrictions, accessible by any client on the LAN."),
    ]:
        db.add(Finding(id=pid(), scan_id=sd_id, severity=sev, title=title,
                       description=desc, created_at=now - timedelta(days=2)))

    for title, sev, asset, status in [
        ("Default Credentials on Core Network Switches", "high",   "10.0.0.1",    "open"),
        ("Telnet Enabled on Network Devices",             "high",   "10.0.0.0/24", "open"),
        ("SNMP v1/v2c with Community String 'public'",   "medium", "10.0.0.0/24", "open"),
    ]:
        db.add(VulnerabilityRecord(id=pid(), project_id=p3_id, title=title,
                                   severity=sev, status=status, affected_asset=asset,
                                   created_at=now - timedelta(days=2)))

    _set(db, "demo_mode", "true")
    db.commit()
    return {"ok": True}


# ── Clear ─────────────────────────────────────────────────────────────────────

@router.delete("/clear")
def clear_demo(db: Session = Depends(get_db)):
    demo_projects = db.query(Project).filter(Project.description == DEMO_MARKER).all()
    project_ids = [p.id for p in demo_projects]

    if project_ids:
        # Delete tables that don't cascade from Project
        db.query(VulnerabilityRecord).filter(
            VulnerabilityRecord.project_id.in_(project_ids)
        ).delete(synchronize_session=False)
        db.query(Credential).filter(
            Credential.project_id.in_(project_ids)
        ).delete(synchronize_session=False)
        # Delete projects — cascades to Target → Scan → Finding
        for p in demo_projects:
            db.delete(p)

    _set(db, "demo_mode", "false")
    db.commit()
    return {"ok": True}
