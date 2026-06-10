"""Nessus / Tenable.io integration — import scan findings into Seraph."""
import json
import uuid
from datetime import datetime
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import AppSetting, Finding, Project, Scan, Target, get_db
from services.vault import decrypt, encrypt

router = APIRouter(prefix="/nessus", tags=["nessus"])

_TENABLE_HOST = "api.tenable.com"

# ── AppSetting helpers ────────────────────────────────────────────────────────

def _get_setting(db: Session, key: str, default: str = "") -> str:
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    return row.value if row else default


def _set_setting(db: Session, key: str, value: str) -> None:
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

    def _headers(self) -> dict:
        if self.auth_type == "apikey":
            return {
                "X-ApiKeys": f"accessKey={self.api_access_key};secretKey={self.api_secret_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        return {
            "X-Cookie": f"token={self._token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _client(self) -> httpx.Client:
        return httpx.Client(verify=self.verify, timeout=30)

    def authenticate(self) -> None:
        if self.auth_type == "apikey":
            return  # no session needed
        with self._client() as c:
            resp = c.post(
                f"{self.base}/session",
                json={"username": self.username, "password": self.password},
            )
            resp.raise_for_status()
            self._token = resp.json().get("token", "")

    def get(self, path: str) -> dict:
        with self._client() as c:
            resp = c.get(f"{self.base}{path}", headers=self._headers())
            resp.raise_for_status()
            return resp.json()


def _load_client(db: Session) -> NessusClient:
    host = _get_setting(db, "nessus_host")
    port = int(_get_setting(db, "nessus_port", "8834"))
    verify_ssl = _get_setting(db, "nessus_verify_ssl", "false").lower() == "true"
    auth_type = _get_setting(db, "nessus_auth_type", "session")
    username = _get_setting(db, "nessus_username")
    try:
        password = decrypt(_get_setting(db, "nessus_password")) if _get_setting(db, "nessus_password") else ""
    except Exception:
        password = ""
    try:
        api_access_key = decrypt(_get_setting(db, "nessus_api_access_key")) if _get_setting(db, "nessus_api_access_key") else ""
        api_secret_key = decrypt(_get_setting(db, "nessus_api_secret_key")) if _get_setting(db, "nessus_api_secret_key") else ""
    except Exception:
        api_access_key = api_secret_key = ""

    if not host:
        raise HTTPException(400, "Nessus not configured — save credentials first")

    return NessusClient(host, port, verify_ssl, auth_type, username, password, api_access_key, api_secret_key)


# ── Severity mapping ─────────────────────────────────────────────────────────

_NESSUS_SEV = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/status")
def nessus_status(db: Session = Depends(get_db)):
    configured = bool(_get_setting(db, "nessus_host"))
    if not configured:
        return {"configured": False, "connected": False, "error": "Not configured"}
    try:
        client = _load_client(db)
        client.authenticate()
        client.get("/server/status")
        return {"configured": True, "connected": True, "error": None}
    except HTTPException as e:
        return {"configured": True, "connected": False, "error": e.detail}
    except Exception as e:
        return {"configured": True, "connected": False, "error": str(e)}


class NessusConfigRequest(BaseModel):
    host: str
    port: int = 8834
    username: str = ""
    password: str = ""
    verify_ssl: bool = False
    api_access_key: str = ""
    api_secret_key: str = ""


@router.post("/config")
def save_nessus_config(req: NessusConfigRequest, db: Session = Depends(get_db)):
    auth_type = "apikey" if req.host.strip().rstrip("/") == _TENABLE_HOST else "session"
    _set_setting(db, "nessus_host", req.host.strip().rstrip("/"))
    _set_setting(db, "nessus_port", str(req.port))
    _set_setting(db, "nessus_username", req.username)
    _set_setting(db, "nessus_verify_ssl", "true" if req.verify_ssl else "false")
    _set_setting(db, "nessus_auth_type", auth_type)
    if req.password:
        _set_setting(db, "nessus_password", encrypt(req.password))
    if req.api_access_key:
        _set_setting(db, "nessus_api_access_key", encrypt(req.api_access_key))
    if req.api_secret_key:
        _set_setting(db, "nessus_api_secret_key", encrypt(req.api_secret_key))
    db.commit()
    return {"ok": True, "auth_type": auth_type}


@router.get("/config")
def get_nessus_config(db: Session = Depends(get_db)):
    return {
        "host": _get_setting(db, "nessus_host"),
        "port": int(_get_setting(db, "nessus_port", "8834")),
        "username": _get_setting(db, "nessus_username"),
        "auth_type": _get_setting(db, "nessus_auth_type", "session"),
        "verify_ssl": _get_setting(db, "nessus_verify_ssl", "false") == "true",
    }


@router.get("/scans")
def list_nessus_scans(db: Session = Depends(get_db)):
    client = _load_client(db)
    try:
        client.authenticate()
        data = client.get("/scans")
    except Exception as e:
        raise HTTPException(502, f"Nessus error: {e}")
    scans = data.get("scans") or []
    return [
        {
            "id": s.get("id"),
            "name": s.get("name", ""),
            "status": s.get("status", ""),
            "last_modification_date": s.get("last_modification_date"),
            "host_count": s.get("hosts_total", 0),
        }
        for s in scans
    ]


@router.get("/scans/{nessus_scan_id}")
def get_nessus_scan(nessus_scan_id: int, db: Session = Depends(get_db)):
    client = _load_client(db)
    try:
        client.authenticate()
        data = client.get(f"/scans/{nessus_scan_id}")
    except Exception as e:
        raise HTTPException(502, f"Nessus error: {e}")
    hosts = [
        {"host_id": h.get("host_id"), "hostname": h.get("hostname", ""),
         "critical": h.get("critical", 0), "high": h.get("high", 0),
         "medium": h.get("medium", 0), "low": h.get("low", 0), "info": h.get("info", 0)}
        for h in (data.get("hosts") or [])
    ]
    return {"id": nessus_scan_id, "name": data.get("info", {}).get("name", ""), "hosts": hosts}


class NessusImportRequest(BaseModel):
    project_id: str = ""
    project_name: str = ""
    host_ids: list[int] = []


def _detect_target_type(os_str: str) -> str:
    s = os_str.lower()
    if "windows" in s:
        return "windows_host"
    if any(x in s for x in ["cisco", "juniper", "fortinet", "palo alto", "vyos", "mikrotik"]):
        return "network"
    return "linux_host"


@router.post("/scans/{nessus_scan_id}/import")
def import_nessus_scan(nessus_scan_id: int, req: NessusImportRequest, db: Session = Depends(get_db)):
    """Import selected hosts + vulnerabilities from a Nessus scan as Seraph Findings."""
    # Resolve or create project
    if req.project_id:
        project = db.query(Project).filter(Project.id == req.project_id).first()
        if not project:
            raise HTTPException(404, "Project not found")
        project_id = req.project_id
    elif req.project_name.strip():
        project = Project(
            id=str(uuid.uuid4()),
            name=req.project_name.strip(),
            description="Imported from Nessus",
        )
        db.add(project)
        db.flush()
        project_id = project.id
    else:
        raise HTTPException(400, "Provide either project_id or project_name")

    client = _load_client(db)
    try:
        client.authenticate()
        scan_data = client.get(f"/scans/{nessus_scan_id}")
    except Exception as e:
        raise HTTPException(502, f"Nessus error: {e}")

    scan_name = scan_data.get("info", {}).get("name", f"Nessus scan {nessus_scan_id}")
    hosts = scan_data.get("hosts") or []
    filter_ids = set(req.host_ids) if req.host_ids else None

    scan_ids: list[str] = []
    findings_created = 0
    hosts_processed = 0
    targets_created = 0

    for host in hosts:
        host_id = host.get("host_id")
        if filter_ids is not None and host_id not in filter_ids:
            continue

        hostname = host.get("hostname", f"host-{host_id}")

        # Fetch per-host detail early — needed for target enrichment
        host_data: dict = {}
        try:
            host_data = client.get(f"/scans/{nessus_scan_id}/hosts/{host_id}")
        except Exception:
            pass

        host_info = host_data.get("info", {})
        real_ip = host_info.get("host-ip", "").strip()
        primary_id = real_ip or hostname

        # Find or create Target
        target = db.query(Target).filter(
            Target.project_id == project_id,
            Target.hostname_or_ip == primary_id,
        ).first()
        if not target:
            os_str = host_info.get("operating-system", "")
            target_type = _detect_target_type(os_str)
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

            # Collect open ports from vulnerabilities
            ports = sorted({
                v.get("port") for v in (host_data.get("vulnerabilities") or [])
                if v.get("port", 0) > 0
            })

            target = Target(
                id=str(uuid.uuid4()),
                project_id=project_id,
                hostname_or_ip=primary_id,
                target_type=target_type,
                notes="\n".join(notes_parts),
                ports=",".join(str(p) for p in ports) if ports else None,
            )
            db.add(target)
            db.flush()
            targets_created += 1

        # Create Scan record for this host
        scan = Scan(
            id=str(uuid.uuid4()),
            target_id=target.id,
            scan_type="nessus_import",
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
            severity_int = vuln.get("severity", 0)
            severity = _NESSUS_SEV.get(severity_int, "info")
            plugin_name = vuln.get("plugin_name", f"Plugin {plugin_id}")

            description = ""
            cve_id = None
            try:
                plugin_data = client.get(f"/scans/{nessus_scan_id}/hosts/{host_id}/plugins/{plugin_id}")
                outputs = plugin_data.get("outputs") or []
                if outputs:
                    description = outputs[0].get("plugin_output", "")
                attrs = plugin_data.get("info", {}).get("plugindescription", {}).get("pluginattributes", {})
                ref_info = attrs.get("ref_information", {})
                refs = ref_info.get("ref", [])
                if isinstance(refs, dict):
                    refs = [refs]
                for ref in refs:
                    if ref.get("name", "").upper() == "CVE":
                        cve_id = ref.get("values", {}).get("value", "")
                        if isinstance(cve_id, list):
                            cve_id = cve_id[0]
                        break
            except Exception:
                pass

            f = Finding(
                id=str(uuid.uuid4()),
                scan_id=scan.id,
                severity=severity,
                title=plugin_name,
                description=description or None,
                control_id=str(plugin_id),
                framework="Nessus",
                cve_id=cve_id or None,
                status="open",
                tags="nessus",
            )
            db.add(f)
            findings_created += 1

        hosts_processed += 1

    db.commit()
    return {
        "scan_ids": scan_ids,
        "findings_created": findings_created,
        "hosts_processed": hosts_processed,
        "targets_created": targets_created,
        "project_id": project_id,
    }
