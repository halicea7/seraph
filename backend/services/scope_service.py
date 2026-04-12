"""
Scope enforcement helpers.

A project's scope_json looks like:
    {"include": ["192.168.1.0/24", "example.com"], "exclude": ["192.168.1.1"]}

If scope_json is None or include list is empty, everything is considered in-scope.
Exclude rules are checked first and take priority over includes.
Both CIDR ranges and exact hostname/wildcard patterns are supported.
"""

import fnmatch
import ipaddress
import json
from typing import Optional


def _matches(target: str, rule: str) -> bool:
    """Return True if target matches the rule (CIDR, exact, or wildcard)."""
    # Try CIDR network match
    try:
        network = ipaddress.ip_network(rule, strict=False)
        try:
            return ipaddress.ip_address(target) in network
        except ValueError:
            pass
    except ValueError:
        pass
    # Wildcard / exact string match (case-insensitive)
    return fnmatch.fnmatch(target.lower(), rule.lower())


def check_scope(target: str, scope_json: Optional[str]) -> tuple[bool, str]:
    """
    Returns (in_scope, reason).
    - in_scope=True  → target is allowed
    - in_scope=False → reason explains why it's blocked
    """
    if not scope_json:
        return True, ""

    try:
        scope = json.loads(scope_json)
    except Exception:
        return True, ""

    include = scope.get("include", [])
    exclude = scope.get("exclude", [])

    if not include:
        # No include rules defined → everything in scope
        return True, ""

    for excl in exclude:
        if _matches(target, excl):
            return False, f"Explicitly excluded ({excl})"

    for incl in include:
        if _matches(target, incl):
            return True, ""

    return False, "Not in defined scope"


def scope_summary(scope_json: Optional[str]) -> dict:
    """Return a dict with include/exclude lists for API responses."""
    if not scope_json:
        return {"include": [], "exclude": []}
    try:
        s = json.loads(scope_json)
        return {"include": s.get("include", []), "exclude": s.get("exclude", [])}
    except Exception:
        return {"include": [], "exclude": []}
