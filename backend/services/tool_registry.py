import shutil
import subprocess
from typing import Dict, Optional

from config import settings


def _get_version(tool_name: str, path: str) -> Optional[str]:
    """Attempt to retrieve a version string for a tool without user-controlled input."""
    # Only run tools from the known tools list — never interpolate user input
    version_flags = ["--version", "-V", "-v", "version"]
    for flag in version_flags:
        try:
            result = subprocess.run(
                [path, flag],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = (result.stdout or result.stderr or "").strip()
            if output:
                # Return first non-empty line
                first_line = output.splitlines()[0]
                return first_line[:120]  # cap length
        except (subprocess.TimeoutExpired, OSError, PermissionError):
            continue
    return None


def detect_tools() -> Dict[str, Dict]:
    """
    Check which tools from the configured list are available on PATH.
    Returns a dict keyed by tool name with availability, path, and version.
    """
    results: Dict[str, Dict] = {}

    for tool in settings.tools:
        path = shutil.which(tool)
        available = path is not None
        version: Optional[str] = None

        if available and path:
            version = _get_version(tool, path)

        results[tool] = {
            "available": available,
            "path": path,
            "version": version,
        }

    return results


# Module-level registry cache — populated on startup
_registry: Dict[str, Dict] = {}


def initialize_registry() -> None:
    global _registry
    _registry = detect_tools()


def get_registry() -> Dict[str, Dict]:
    return _registry
