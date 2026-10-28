"""
Scan lifecycle — the canonical writer for Finding rows, for every path that
produces them (tool-output parsing, OSINT, CIS-CAT import, agent results,
auto-probe, playbooks).

Upserts by fingerprint (cve_id + control_id + normalized title) instead of
delete-then-recreate or blind insert, so analyst triage (status, fp_reason,
tags, exploit_chain_json) on an existing row survives a rescan, and a tool
re-run doesn't pile up duplicate findings.

Two dedup scopes are needed, not one:
  - scan-scoped (default): the caller reuses the same Scan row across runs
    (e.g. re-parsing a scan's raw_output, re-running a terminal command).
    Existing rows are looked up by scan_id.
  - target-scoped (`dedupe_by_target=True`): the caller creates a brand-new
    Scan row every run (auto-probe and playbooks create one Scan per tool
    invocation/step), so scan-scoped lookup would never find a match and
    every run would duplicate the same findings. Existing rows are looked
    up across every Scan belonging to the same target instead; new rows
    still attach to the current scan.
"""

import hashlib
import re
import uuid
from typing import Optional

from services.output_parser import ParsedFinding, auto_parse_scan_output

__all__ = ["fingerprint_for", "upsert_findings", "save_parsed_findings", "record_output_hash"]


def record_output_hash(scan, raw_output: str) -> None:
    """Chain-of-custody: hash raw_output as it's finalized, so a later
    edit to the stored text (or a DB-level tamper) is detectable. Callers
    that build raw_output themselves and don't go through
    save_parsed_findings (e.g. websocket_osint, CIS-CAT import) call this
    directly, right alongside `scan.raw_output = raw_output`."""
    scan.output_hash = hashlib.sha256((raw_output or "").encode()).hexdigest()


def _normalize_title(t: Optional[str]) -> str:
    return re.sub(r"\s+", " ", (t or "").lower().strip())


def fingerprint_for(cve_id: Optional[str], control_id: Optional[str], title: Optional[str]) -> str:
    """Identity of a finding — same shape as routers/projects.py:_finding_fingerprint,
    minus the target_id component (callers that need target-scoping pass
    dedupe_by_target=True to upsert_findings instead)."""
    return f"{(cve_id or '').upper()}|{control_id or ''}|{_normalize_title(title)}"


def upsert_findings(db, scan, parsed: list[ParsedFinding], dedupe_by_target: bool = False) -> tuple[list, int]:
    """Upsert already-parsed findings against existing Finding rows.

    Returns (all_current_findings, new_finding_count).
    """
    from database import Finding, Scan as ScanModel

    if not parsed:
        return [], 0

    query = db.query(Finding)
    if dedupe_by_target:
        query = query.join(ScanModel, Finding.scan_id == ScanModel.id).filter(ScanModel.target_id == scan.target_id)
    else:
        query = query.filter(Finding.scan_id == scan.id)
    existing = query.all()

    existing_by_fp: dict[str, Finding] = {}
    for f in existing:
        existing_by_fp.setdefault(fingerprint_for(f.cve_id, f.control_id, f.title), f)

    all_current: list = []
    new_count = 0
    for pf in parsed:
        fp = fingerprint_for(pf.cve_id, pf.control_id, pf.title)
        row = existing_by_fp.get(fp)
        if row:
            row.title = pf.title
            row.description = pf.description
            row.severity = pf.severity
            row.control_id = pf.control_id
            row.framework = pf.framework
            row.remediation = pf.remediation
            row.evidence = pf.evidence
            row.cve_id = pf.cve_id
            row.fingerprint = fp
            all_current.append(row)
        else:
            row = Finding(
                id=str(uuid.uuid4()),
                scan_id=scan.id,
                title=pf.title,
                description=pf.description,
                severity=pf.severity,
                control_id=pf.control_id,
                framework=pf.framework,
                remediation=pf.remediation,
                evidence=pf.evidence,
                cve_id=pf.cve_id,
                tags=",".join(t for t in (pf.extra_tags or []) if t),
                status=pf.status or "open",
                fingerprint=fp,
            )
            db.add(row)
            all_current.append(row)
            new_count += 1

    db.commit()
    return all_current, new_count


def save_parsed_findings(db, scan, raw_output: str, dedupe_by_target: bool = False) -> tuple[list, int]:
    """Parse `raw_output` for `scan` and upsert the resulting Finding rows.

    See `upsert_findings` for the dedup-scope contract; see
    `services.output_parser.auto_parse_scan_output` for parsing.
    """
    record_output_hash(scan, raw_output)
    parsed = auto_parse_scan_output(scan.scan_type, raw_output)
    if not parsed:
        return [], 0
    return upsert_findings(db, scan, parsed, dedupe_by_target=dedupe_by_target)
