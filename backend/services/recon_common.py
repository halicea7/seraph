"""Shared helpers between the two recon-driving engines: auto_probe.py's
auto-probe loop and playbook_runner.py's playbook steps. Both parse nmap
output for open ports the same way, and both create one pending Scan row
per tool invocation/step the same way -- just with a different config_json
payload, which callers still build themselves.
"""
import json
import re
import uuid

from database import Scan, SessionLocal

_OPEN_PORT_RE = re.compile(r"(\d+)/tcp\s+open")


def extract_open_ports(output: str) -> set[int]:
    return {int(m.group(1)) for m in _OPEN_PORT_RE.finditer(output)}


def create_pending_scan(target_id: str, scan_type: str, config: dict) -> str:
    """Create a pending Scan row for one tool invocation/step. Returns its id."""
    db = SessionLocal()
    try:
        scan = Scan(
            id=str(uuid.uuid4()),
            target_id=target_id,
            scan_type=scan_type,
            module="pentest",
            status="pending",
            config_json=json.dumps(config),
        )
        db.add(scan)
        db.commit()
        return scan.id
    finally:
        db.close()
