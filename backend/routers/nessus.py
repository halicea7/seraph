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
    project_id: str


@router.post("/scans/{nessus_scan_id}/import")
def import_nessus_scan(nessus_scan_id: int, req: NessusImportRequest, db: Session = Depends(get_db)):
    """Import all hosts + vulnerabilities from a Nessus scan as Seraph Findings."""
    project = db.query(Project).filter(Project.id == req.project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")

    client = _load_client(db)
    try:
        client.authenticate()
        scan_data = client.get(f"/scans/{nessus_scan_id}")
    except Exception as e:
        raise HTTPException(502, f"Nessus error: {e}")

    scan_name = scan_data.get("info", {}).get("name", f"Nessus scan {nessus_scan_id}")
    hosts = scan_data.get("hosts") or []

    scan_ids: list[str] = []
    findings_created = 0
    hosts_processed = 0

    for host in hosts:
        host_id = host.get("host_id")
        hostname = host.get("hostname", f"host-{host_id}")

        # Find or create Target
        target = db.query(Target).filter(
            Target.project_id == req.project_id,
            Target.hostname_or_ip == hostname,
        ).first()
        if not target:
            target = Target(
                id=str(uuid.uuid4()),
                project_id=req.project_id,
                hostname_or_ip=hostname,
                target_type="linux_host",
            )
            db.add(target)
            db.flush()

        # Create a Scan record for this host
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

        # Fetch per-host vulnerabilities
        try:
            host_data = client.get(f"/scans/{nessus_scan_id}/hosts/{host_id}")
        except Exception:
            continue

        for vuln in (host_data.get("vulnerabilities") or []):
            plugin_id = vuln.get("plugin_id")
            severity_int = vuln.get("severity", 0)
            severity = _NESSUS_SEV.get(severity_int, "info")
            plugin_name = vuln.get("plugin_name", f"Plugin {plugin_id}")

            # Fetch plugin output for CVE data (best-effort)
            description = ""
            cve_id = None
            try:
                plugin_data = client.get(f"/scans/{nessus_scan_id}/hosts/{host_id}/plugins/{plugin_id}")
                outputs = plugin_data.get("outputs") or []
                if outputs:
                    description = outputs[0].get("plugin_output", "")
                # CVE IDs are in plugin attributes
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
    return {"scan_ids": scan_ids, "findings_created": findings_created, "hosts_processed": hosts_processed}
