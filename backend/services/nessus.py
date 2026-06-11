"""Nessus / Tenable.io client + shared helpers.

Extracted from routers/nessus.py so both the HTTP routes and the background
poller (services/scheduler.py) can share one client implementation. Supports
API-key auth (Tenable.io) and session-token auth (on-prem Nessus), with token
reuse and a light retry on expiry.
"""
import json
import uuid
from datetime import datetime
from typing import Optional

import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

from database import AppSetting, Finding, Scan, Target
from services.vault import decrypt

_TENABLE_HOST = "api.tenable.com"

# Nessus plugin severity (0–4) → Seraph severity enum
_NESSUS_SEV = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


# ── AppSetting helpers ────────────────────────────────────────────────────────

def get_setting(db: Session, key: str, default: str = "") -> str:
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    return row.value if row else default


def set_setting(db: Session, key: str, value: str) -> None:
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(AppSetting(key=key, value=value))


# ── Nessus HTTP client ────────────────────────────────────────────────────────

class NessusClient:
    def __init__(self, host: str, port: int, verify_ssl: bool, auth_type: str,
                 username: str = "", password: str = "",
                 api_access_key: str = "", api_secret_key: str = ""):
        self.base = f"https://{host}:{port}"
        self.verify = verify_ssl
        self.auth_type = auth_type
        self.username = username
        self.password = password
        self.api_access_key = api_access_key
        self.api_secret_key = api_secret_key
        self._token: str = ""

    def _headers(self, json_body: bool = True) -> dict:
        h = {"Accept": "application/json"}
        if json_body:
            h["Content-Type"] = "application/json"
        if self.auth_type == "apikey":
            h["X-ApiKeys"] = f"accessKey={self.api_access_key};secretKey={self.api_secret_key}"
        else:
            h["X-Cookie"] = f"token={self._token}"
        return h

    def _client(self) -> httpx.Client:
        return httpx.Client(verify=self.verify, timeout=60)

    def authenticate(self, force: bool = False) -> None:
        """Establish a session token (session auth only). Reused across calls."""
        if self.auth_type == "apikey":
            return
        if self._token and not force:
            return
        with self._client() as c:
            resp = c.post(
                f"{self.base}/session",
                json={"username": self.username, "password": self.password},
            )
            resp.raise_for_status()
            self._token = resp.json().get("token", "")

    def _request(self, method: str, path: str, *, json_body: Optional[dict] = None,
                 raw: bool = False, _retried: bool = False):
        self.authenticate()
        with self._client() as c:
            resp = c.request(
                method, f"{self.base}{path}",
                headers=self._headers(json_body=json_body is not None or method in ("POST", "PUT")),
                json=json_body,
            )
        # Session token expired → re-auth once and retry.
        if resp.status_code == 401 and self.auth_type != "apikey" and not _retried:
            self.authenticate(force=True)
            return self._request(method, path, json_body=json_body, raw=raw, _retried=True)
        resp.raise_for_status()
        if raw:
            return resp.content
        if not resp.content:
            return {}
        return resp.json()

    def get(self, path: str) -> dict:
        return self._request("GET", path)

    def post(self, path: str, json_body: Optional[dict] = None) -> dict:
        return self._request("POST", path, json_body=json_body or {})

    def put(self, path: str, json_body: Optional[dict] = None) -> dict:
        return self._request("PUT", path, json_body=json_body or {})

    def delete(self, path: str) -> dict:
        return self._request("DELETE", path)

    def download(self, path: str) -> bytes:
        return self._request("GET", path, raw=True)


def load_client(db: Session) -> NessusClient:
    host = get_setting(db, "nessus_host")
    port = int(get_setting(db, "nessus_port", "8834"))
    verify_ssl = get_setting(db, "nessus_verify_ssl", "false").lower() == "true"
    auth_type = get_setting(db, "nessus_auth_type", "session")
    username = get_setting(db, "nessus_username")
    try:
        password = decrypt(get_setting(db, "nessus_password")) if get_setting(db, "nessus_password") else ""
    except Exception:
        password = ""
    try:
        api_access_key = decrypt(get_setting(db, "nessus_api_access_key")) if get_setting(db, "nessus_api_access_key") else ""
        api_secret_key = decrypt(get_setting(db, "nessus_api_secret_key")) if get_setting(db, "nessus_api_secret_key") else ""
    except Exception:
        api_access_key = api_secret_key = ""

    if not host:
        raise HTTPException(400, "Nessus not configured — save credentials first")

    return NessusClient(host, port, verify_ssl, auth_type, username, password, api_access_key, api_secret_key)


# ── Target type heuristic ─────────────────────────────────────────────────────

def detect_target_type(os_str: str) -> str:
    s = (os_str or "").lower()
    if "windows" in s:
        return "windows_host"
    if any(x in s for x in ["cisco", "juniper", "fortinet", "palo alto", "vyos", "mikrotik"]):
        return "network"
    return "linux_host"


# ── Rich plugin-detail extraction ─────────────────────────────────────────────

def _first(value):
    """Nessus refs come back as either a value, a dict {value:..}, or a list."""
    if isinstance(value, dict):
        value = value.get("value")
    if isinstance(value, list):
        return value[0] if value else None
    return value


def parse_plugin_detail(plugin_data: dict, vuln_row: dict) -> dict:
    """Pull CVSS / solution / synopsis / references / CVE from a Nessus plugin
    detail response (GET scans/{id}/hosts/{host}/plugins/{plugin})."""
    out = {
        "description": "", "remediation": None, "evidence": None,
        "cvss_score": None, "cve_id": None,
    }
    outputs = plugin_data.get("outputs") or []
    plugin_output = ""
    if outputs:
        plugin_output = outputs[0].get("plugin_output", "") or ""

    attrs = (plugin_data.get("info", {})
             .get("plugindescription", {})
             .get("pluginattributes", {}))

    synopsis = attrs.get("synopsis", "") or ""
    description = attrs.get("description", "") or ""
    solution = attrs.get("solution", "") or ""

    # Description block: synopsis + description, evidence holds raw plugin output.
    desc_parts = [p for p in (synopsis, description) if p]
    out["description"] = "\n\n".join(desc_parts) or plugin_output or ""
    out["evidence"] = plugin_output or None
    out["remediation"] = solution or None

    # CVSS — prefer v3 base, fall back to v2 base.
    risk = attrs.get("risk_information", {}) or {}
    cvss = risk.get("cvss3_base_score") or risk.get("cvss_base_score")
    out["cvss_score"] = str(cvss) if cvss else None

    # CVE from ref_information.
    ref_info = attrs.get("ref_information", {}) or {}
    refs = ref_info.get("ref", [])
    if isinstance(refs, dict):
        refs = [refs]
    for ref in refs:
        if str(ref.get("name", "")).upper() == "CVE":
            out["cve_id"] = _first(ref.get("values"))
            break

    # Append see_also references to the description.
    see_also = attrs.get("see_also")
    if see_also:
        if isinstance(see_also, str):
            see_also = [see_also]
        if isinstance(see_also, list) and see_also:
            out["description"] = (out["description"] + "\n\nReferences:\n" +
                                  "\n".join(str(s) for s in see_also)).strip()
    return out


# ── Import (reusable by routes + poller) ──────────────────────────────────────

def import_scan_results(db: Session, client: NessusClient, nessus_scan_id: int,
                        project_id: str, host_ids: Optional[list[int]] = None) -> dict:
    """Import selected hosts + vulnerabilities from a Nessus scan as Seraph
    Findings. Deduplicates: a finding is skipped if one with the same plugin id
    (control_id) already exists for that target.
    """
    scan_data = client.get(f"/scans/{nessus_scan_id}")
    scan_name = scan_data.get("info", {}).get("name", f"Nessus scan {nessus_scan_id}")
    hosts = scan_data.get("hosts") or []
    filter_ids = set(host_ids) if host_ids else None

    scan_ids: list[str] = []
    findings_created = 0
    findings_skipped = 0
    hosts_processed = 0
    targets_created = 0

    for host in hosts:
        host_id = host.get("host_id")
        if filter_ids is not None and host_id not in filter_ids:
            continue

        hostname = host.get("hostname", f"host-{host_id}")
        try:
            host_data = client.get(f"/scans/{nessus_scan_id}/hosts/{host_id}")
        except Exception:
            host_data = {}

        host_info = host_data.get("info", {})
        real_ip = (host_info.get("host-ip", "") or "").strip()
        primary_id = real_ip or hostname

        target = db.query(Target).filter(
            Target.project_id == project_id,
            Target.hostname_or_ip == primary_id,
        ).first()
        if not target:
            os_str = host_info.get("operating-system", "")
            notes_parts = []
            if os_str:
                notes_parts.append(f"OS: {os_str}")
            fqdn = host_info.get("host-fqdn", "")
            if fqdn and fqdn != primary_id:
                notes_parts.append(f"FQDN: {fqdn}")
            mac = host_info.get("mac-address", "")
            if mac:
                notes_parts.append(f"MAC: {mac}")
            nb = host_info.get("netbios-name", "")
            if nb:
                notes_parts.append(f"NetBIOS: {nb}")
            notes_parts.append("Source: Nessus import")

            ports = sorted({
                v.get("port") for v in (host_data.get("vulnerabilities") or [])
                if v.get("port", 0) > 0
            })

            target = Target(
                id=str(uuid.uuid4()),
                project_id=project_id,
                hostname_or_ip=primary_id,
                target_type=detect_target_type(os_str),
                notes="\n".join(notes_parts),
                ports=",".join(str(p) for p in ports) if ports else None,
            )
            db.add(target)
            db.flush()
            targets_created += 1

        # Plugin ids already recorded for this target (dedupe key).
        existing_plugins = {
            row[0] for row in db.query(Finding.control_id)
            .join(Scan, Finding.scan_id == Scan.id)
            .filter(Scan.target_id == target.id, Finding.control_id.isnot(None))
            .all()
        }

        scan = Scan(
            id=str(uuid.uuid4()),
            target_id=target.id,
            scan_type="nessus",
            module="pentest",
            status="completed",
            config_json=json.dumps({"nessus_scan_id": nessus_scan_id, "scan_name": scan_name}),
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
        )
        db.add(scan)
        db.flush()
        scan_ids.append(scan.id)

        for vuln in (host_data.get("vulnerabilities") or []):
            plugin_id = vuln.get("plugin_id")
            if str(plugin_id) in existing_plugins:
                findings_skipped += 1
                continue
            severity = _NESSUS_SEV.get(vuln.get("severity", 0), "info")
            plugin_name = vuln.get("plugin_name", f"Plugin {plugin_id}")
            port = vuln.get("port")
            protocol = vuln.get("protocol", "")

            detail = {"description": "", "remediation": None, "evidence": None,
                      "cvss_score": None, "cve_id": None}
            try:
                plugin_data = client.get(
                    f"/scans/{nessus_scan_id}/hosts/{host_id}/plugins/{plugin_id}")
                detail = parse_plugin_detail(plugin_data, vuln)
            except Exception:
                pass

            tags = "nessus"
            if port and protocol:
                tags += f",{protocol}/{port}"

            f = Finding(
                id=str(uuid.uuid4()),
                scan_id=scan.id,
                severity=severity,
                title=plugin_name,
                description=detail["description"] or None,
                remediation=detail["remediation"],
                evidence=detail["evidence"],
                control_id=str(plugin_id),
                framework="Nessus",
                cve_id=detail["cve_id"] or None,
                cvss_score=detail["cvss_score"],
                status="open",
                tags=tags,
            )
            db.add(f)
            existing_plugins.add(str(plugin_id))
            findings_created += 1

        hosts_processed += 1

    db.commit()
    return {
        "scan_ids": scan_ids,
        "findings_created": findings_created,
        "findings_skipped": findings_skipped,
        "hosts_processed": hosts_processed,
        "targets_created": targets_created,
        "project_id": project_id,
        "scan_name": scan_name,
    }
