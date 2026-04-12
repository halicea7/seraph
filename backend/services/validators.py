"""Reusable input validators for Seraph API endpoints.

All validators raise ValueError on invalid input so they compose cleanly
with Pydantic field_validator decorators.
"""
import re

# ── Hostname / IP ──────────────────────────────────────────────────────────────

_HOSTNAME_IP_RE = re.compile(
    r"^(?:"
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"  # IPv4
    r"|"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"  # hostname/FQDN
    r")$"
)

# CIDR notation (used in scope rules)
_CIDR_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"/(?:[12]?\d|3[0-2])$"
)

# Domain only (no bare IPs, used for OSINT tools that require domain names)
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

def validate_hostname_or_ip(value: str, *, allow_empty: bool = False) -> str:
    """Accept a valid IPv4 address or DNS hostname. Rejects shell metacharacters."""
    if allow_empty and not value:
        return value
    if not value:
        raise ValueError("Value must not be empty")
    if len(value) > 253:
        raise ValueError("Hostname/IP too long (max 253 chars)")
    if _HOSTNAME_IP_RE.match(value):
        return value
    if _CIDR_RE.match(value):
        return value
    raise ValueError(f"Invalid hostname or IP address: {value!r}")


def validate_domain(value: str) -> str:
    """Accept a valid DNS domain name (not a bare IP)."""
    if not value:
        raise ValueError("Domain must not be empty")
    if len(value) > 253:
        raise ValueError("Domain name too long (max 253 chars)")
    if not _DOMAIN_RE.match(value):
        raise ValueError(f"Invalid domain name: {value!r}")
    return value


# ── Enumerated string fields ────────────────────────────────────────────────────

VALID_TARGET_TYPES = frozenset({
    "linux_host", "windows_host", "web_app",
    "cloud_aws", "cloud_azure", "cloud_gcp",
    "network", "api_endpoint",
})

VALID_CRED_TYPES = frozenset({"password", "hash", "key", "token", "other"})
VALID_CRED_SOURCES = frozenset({"manual", "c2_loot", "osint", "brute_force"})
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})


def validate_enum(value: str, allowed: frozenset, field_name: str = "value") -> str:
    if value not in allowed:
        raise ValueError(f"{field_name} must be one of: {', '.join(sorted(allowed))}")
    return value


# ── Free-text / notes fields ────────────────────────────────────────────────────

_NULL_BYTE_RE = re.compile(r"\x00")

def validate_free_text(value: str, *, max_length: int = 4096, field_name: str = "value") -> str:
    """Strip null bytes and enforce a max length. Does not restrict content otherwise."""
    if _NULL_BYTE_RE.search(value):
        raise ValueError(f"{field_name} must not contain null bytes")
    if len(value) > max_length:
        raise ValueError(f"{field_name} too long (max {max_length} chars)")
    return value


# ── Command validation (defense-in-depth, templates are primary guard) ──────────

_DISALLOWED_COMMAND_PATTERNS = ["`", "$(", "${IFS}", "eval ", "exec "]

def validate_pentest_command(command: str) -> str:
    """Basic injection guard for pentest commands rendered from tool_chains templates."""
    command = command.strip()
    if not command:
        raise ValueError("Command must not be empty")
    if len(command) > 2048:
        raise ValueError("Command too long (max 2048 chars)")
    for pattern in _DISALLOWED_COMMAND_PATTERNS:
        if pattern in command:
            raise ValueError(f"Disallowed pattern in command: {pattern!r}")
    return command
