"""
SSH executor — runs a bash script on a remote host via SSH.

The private key is written to a temporary file (chmod 600), used for a single
SSH call, then deleted in a finally block regardless of outcome.

Usage:
    async for message in run_script_over_ssh(host, user, private_key_pem, script):
        # message is {"type": "stdout"|"exit", "data": str, "code": int|None}
        ...
"""

import asyncio
import os
import stat
import tempfile
from typing import AsyncIterator


# Scan categories that must run on the target host (not locally)
REMOTE_CATEGORIES = {"host_hardening", "openscap", "log_monitoring"}


async def run_script_over_ssh(
    host: str,
    user: str,
    private_key_pem: str,
    script: str,
    port: int = 22,
) -> AsyncIterator[dict]:
    """Stream output of a bash script executed remotely over SSH."""

    key_fd, key_path = tempfile.mkstemp(prefix="seraph_key_", suffix=".pem")
    script_fd, script_path = tempfile.mkstemp(prefix="seraph_script_", suffix=".sh")
    try:
        # Write private key — 0600 permissions
        os.write(key_fd, private_key_pem.encode())
        os.close(key_fd)
        os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)

        # Write script
        os.write(script_fd, script.encode())
        os.close(script_fd)

        ssh_cmd = [
            "ssh",
            "-i", key_path,
            "-p", str(port),
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=15",
            "-o", "ServerAliveInterval=30",
            f"{user}@{host}",
            "bash -s",
        ]

        with open(script_path, "rb") as script_fh:
            proc = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdin=script_fh,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,  # merge stderr → stdout
            )

        try:
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                yield {"type": "stdout", "data": line.decode(errors="replace"), "code": None}

            await proc.wait()
            yield {"type": "exit", "data": "", "code": proc.returncode}
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
    finally:
        for path in (key_path, script_path):
            try:
                os.unlink(path)
            except OSError:
                pass
