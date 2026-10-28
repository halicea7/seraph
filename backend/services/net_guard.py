"""SSRF guard — reject outbound URLs/hosts that resolve to private, loopback,
or link-local addresses (RFC1918, 127.0.0.0/8, 169.254.0.0/16 incl. the cloud
metadata endpoint, ::1, fc00::/7, etc).

Used by every service that fetches a user-supplied URL server-side: webhook
delivery, the AI client endpoint, and the Nessus client host. None of these
need to reach the Seraph host's own network — they talk to an external
webhook receiver, an LLM endpoint, or a Nessus server, all of which should be
reachable addresses the operator explicitly configured, not an address that
only resolves to something internal once the request leaves this process.
"""
import ipaddress
import os
import socket
from urllib.parse import urlparse

# Comma-separated list of peer IPs trusted to set X-Forwarded-For (your
# reverse proxy's own address, e.g. "127.0.0.1" or the container gateway).
# Empty by default: nobody is trusted, so rate limiting and login lockout key
# on the real TCP peer address, which a client can't spoof. Any client could
# otherwise set X-Forwarded-For itself to rotate past the rate limit or the
# 5-attempt login lockout, or to frame another IP for a lockout.
_TRUSTED_PROXIES = {
    p.strip() for p in os.environ.get("SERAPH_TRUSTED_PROXIES", "").split(",") if p.strip()
}


def client_ip(peer_ip: str, xff_header: str | None) -> str:
    """Return the IP to key rate limiting / lockout on. Only reads
    X-Forwarded-For when the direct TCP peer is a configured trusted proxy —
    otherwise the header is attacker-controlled and ignored."""
    if peer_ip in _TRUSTED_PROXIES and xff_header:
        return xff_header.split(",")[0].strip()
    return peer_ip or "unknown"


def is_private_or_reserved_host(host: str) -> bool:
    """True if `host` (hostname or literal IP) resolves to a private,
    loopback, link-local, or otherwise non-routable address — or fails to
    resolve at all (fail closed, not open)."""
    if not host:
        return True
    try:
        # getaddrinfo resolves both hostnames and literal IPs uniformly.
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return True
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr.split("%")[0])  # strip IPv6 zone id
        except ValueError:
            return True
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return True
    return False


def is_link_local_host(host: str) -> bool:
    """Narrower check than is_private_or_reserved_host: only link-local
    (169.254.0.0/16, fe80::/10 — this is the range the AWS/GCP/Azure/
    DigitalOcean metadata endpoint lives in, 169.254.169.254). Unlike
    loopback/RFC1918, there is no legitimate reason for an admin-configured
    AI or Nessus endpoint to live here, so this check is safe to apply
    without breaking the common "Ollama/Nessus on localhost or the LAN"
    deployment that is_private_or_reserved_host would block."""
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr.split("%")[0])
        except ValueError:
            continue
        if ip.is_link_local:
            return True
    return False


def check_url(url: str) -> tuple[bool, str]:
    """Return (ok, reason). ok=False if the URL's host is private/reserved,
    or the URL has no host at all."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "Could not parse URL"
    if not parsed.hostname:
        return False, "URL has no host"
    if is_private_or_reserved_host(parsed.hostname):
        return False, f"{parsed.hostname} resolves to a private/reserved address — refusing to request it"
    return True, ""
