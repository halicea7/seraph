"""
Auto-Probe service — fires a lightweight background recon when a target is created.
Each tool runs sequentially in an asyncio coroutine. Results are saved as normal
Scan records with config_json={"auto_probe": true} so the UI can identify them.
"""
import asyncio
import json
import re
import shutil
import uuid
from datetime import datetime

from database import AppSetting, Finding, Notification, Scan, SessionLocal

# Tool definitions — cmd is a callable(host) -> shell string
PROBE_STEPS = [
    {
        "name": "whois",
        "scan_type": "whois",
        "cmd": lambda h: f"whois {h}",
        "always": True,
        "trigger_ports": set(),
    },
    {
        "name": "nmap",
        "scan_type": "nmap",
        "cmd": lambda h: f"nmap -sV -T4 --top-ports 1000 {h}",
        "always": True,
        "trigger_ports": set(),
    },
    {
        "name": "nikto",
        "scan_type": "nikto",
        "cmd": lambda h: f"nikto -h {h}",
        "clamp_timeout": True,   # pass -maxtime to cap runtime
        "always": False,
        "trigger_ports": {80, 443, 8080, 8443, 8000},
    },
    {
        "name": "testssl",
        "scan_type": "testssl",
        "cmd": lambda h: f"testssl --fast {h}",
        "always": False,
        "trigger_ports": {443, 8443},
    },
]

_OPEN_PORT_RE = re.compile(r"(\d+)/tcp\s+open")


def get_probe_config() -> dict:
    """Read auto-probe settings from the DB."""
    db = SessionLocal()
    try:
        def _get(key: str, default: str) -> str:
            row = db.query(AppSetting).filter(AppSetting.key == key).first()
            return row.value if row else default

        enabled = _get("auto_probe_enabled", "false") == "true"
        tools_raw = _get("auto_probe_tools", '["whois","nmap","nikto","testssl"]')
        try:
            tools: list[str] = json.loads(tools_raw)
        except Exception:
            tools = ["whois", "nmap", "nikto", "testssl"]
        intensity = _get("auto_probe_intensity", "standard")
        return {"enabled": enabled, "tools": tools, "intensity": intensity}
    finally:
        db.close()


def _extract_open_ports(nmap_output: str) -> set[int]:
    return {int(m.group(1)) for m in _OPEN_PORT_RE.finditer(nmap_output)}


def _timeout_for_intensity(intensity: str) -> int:
    return {"quick": 120, "standard": 300, "deep": 600}.get(intensity, 300)


async def _run_step(scan_id: str, cmd: str, scan_type: str, timeout: int) -> str | None:
    """Execute one tool, stream output into the Scan record, auto-parse findings."""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return None
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()

    from routers.ws import broadcast_event as _broadcast
    asyncio.create_task(_broadcast({"type": "scan_update", "scan_id": scan_id, "status": "running"}))

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        chunks: list[str] = []
        try:
            async for line in proc.stdout:  # type: ignore[union-attr]
                chunks.append(line.decode(errors="replace"))
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
    except Exception as exc:
        _mark_failed(scan_id, str(exc))
        return None

    output = "".join(chunks)
    status = "completed"
    finding_count = 0

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.raw_output = output
            scan.status = "completed"
            scan.completed_at = datetime.utcnow()
            db.commit()

            # Auto-parse findings
            from services.output_parser import auto_parse_scan_output
            parsed = auto_parse_scan_output(scan_type, output)
            for pf in parsed:
                db.add(Finding(
                    id=str(uuid.uuid4()),
                    scan_id=scan_id,
                    severity=pf.severity,
                    title=pf.title,
                    description=pf.description,
                    control_id=pf.control_id,
                    framework=pf.framework,
                    remediation=pf.remediation,
                    evidence=pf.evidence,
                ))
            if parsed:
                highs = sum(1 for p in parsed if p.severity in ("critical", "high"))
                db.add(Notification(
                    title=f"Auto-probe complete — {len(parsed)} finding(s)",
                    body=f"{scan_type}: {len(parsed)} finding(s)" + (f", {highs} critical/high" if highs else ""),
                    type="critical" if highs > 0 else "info",
                    scan_id=scan_id,
                ))
            db.commit()
            status = scan.status
            finding_count = len(parsed) if parsed else 0
    finally:
        db.close()

    asyncio.create_task(_broadcast({
        "type": "scan_update", "scan_id": scan_id, "status": status,
        "findings": finding_count,
    }))

    return output


def _mark_failed(scan_id: str, reason: str):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.raw_output = reason
            scan.completed_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


def _create_scan(target_id: str, scan_type: str, tool_name: str) -> str:
    db = SessionLocal()
    try:
        scan = Scan(
            id=str(uuid.uuid4()),
            target_id=target_id,
            scan_type=scan_type,
            module="pentest",
            status="pending",
            config_json=json.dumps({"auto_probe": True, "tool": tool_name}),
        )
        db.add(scan)
        db.commit()
        return scan.id
    finally:
        db.close()


async def run_auto_probe(target_id: str, target_host: str, enabled_tools: list[str], intensity: str):
    """Main probe coroutine — runs steps sequentially in the background."""
    timeout = _timeout_for_intensity(intensity)
    nmap_output: str | None = None

    for step in PROBE_STEPS:
        name = step["name"]
        if name not in enabled_tools:
            continue
        if not shutil.which(name):
            continue

        # Conditional steps need nmap results first
        if not step["always"]:
            if nmap_output is None:
                continue
            open_ports = _extract_open_ports(nmap_output)
            if not open_ports.intersection(step["trigger_ports"]):
                continue

        scan_id = _create_scan(target_id, step["scan_type"], name)
        cmd = step["cmd"](target_host)
        if step.get("clamp_timeout"):
            cmd = f"{cmd} -maxtime {timeout}"
        output = await _run_step(scan_id, cmd, step["scan_type"], timeout)

        if name == "nmap" and output:
            nmap_output = output


