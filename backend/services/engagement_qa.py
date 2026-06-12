"""
Engagement Q&A retrieval (RAG).

Lightweight keyword retrieval over an engagement's own data (findings, vulns,
loot, credential metadata, scans) scoped to a project. No embeddings / vector DB —
in-Python token-overlap scoring keeps it infra-free, matching how the rest of the
codebase does FTS-style lookups. Retrieved snippets are assembled into a grounded
prompt for the configured LLM; citations point back at the source rows.

Credential SECRETS are never included — only metadata (type/source/host/user).
"""

import re

from sqlalchemy.orm import Session

from database import (
    Finding, Scan, Target, LootEntry, Credential, VulnerabilityRecord, C2Session,
)

_WORD = re.compile(r"[a-zA-Z0-9_.-]{3,}")

# Common question words that carry no retrieval signal.
_STOPWORDS = {
    "the", "are", "what", "which", "have", "has", "had", "for", "this", "that",
    "and", "our", "with", "from", "was", "were", "you", "your", "any", "all",
    "can", "does", "did", "how", "why", "when", "where", "who", "into", "over",
    "about", "there", "their", "them", "they", "get", "got", "list", "show",
    "tell", "give", "find", "been", "being", "but", "not", "out", "per", "see",
}

# Question keyword → the record type it implies (singular + plural).
_TYPE_HINTS = {
    "finding": "finding", "findings": "finding", "issue": "finding", "issues": "finding",
    "vuln": "vuln", "vulns": "vuln", "vulnerability": "vuln", "vulnerabilities": "vuln",
    "credential": "credential", "credentials": "credential", "cred": "credential",
    "creds": "credential", "password": "credential", "passwords": "credential",
    "hash": "credential", "hashes": "credential",
    "loot": "loot", "scan": "scan", "scans": "scan",
}

_SEVERITIES = {"critical", "high", "medium", "low", "info"}

# Usefulness ranking for Q&A — drives tie-breaks and the no-hit fallback so scan
# rows never crowd out findings/vulns.
_TYPE_PRIORITY = {"finding": 5, "vuln": 4, "loot": 3, "credential": 2, "scan": 1}


def _tokens(text: str | None) -> set[str]:
    return {w.lower() for w in _WORD.findall(text or "") if w.lower() not in _STOPWORDS}


def _gather(db: Session, project_id: str) -> list[dict]:
    """Collect candidate documents for a project. Each: {type, id, title, text}."""
    docs: list[dict] = []

    findings = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
        .filter(Target.project_id == project_id)
        .all()
    )
    for f in findings:
        docs.append({
            "type": "finding", "id": f.id, "title": f.title,
            "text": f"[{f.severity}] {f.title}. {f.description or ''} "
                    f"{f.remediation or ''} cve={f.cve_id or '-'} status={f.status}",
        })

    for v in db.query(VulnerabilityRecord).filter(VulnerabilityRecord.project_id == project_id).all():
        docs.append({
            "type": "vuln", "id": v.id, "title": v.title,
            "text": f"[{v.severity}] {v.title}. {v.description or ''} "
                    f"asset={v.affected_asset or '-'} cve={v.cve_id or '-'} status={v.status}",
        })

    loot = (
        db.query(LootEntry)
        .join(C2Session, LootEntry.session_id == C2Session.id)
        .filter(C2Session.project_id == project_id)
        .all()
    )
    for l in loot:
        docs.append({
            "type": "loot", "id": l.id, "title": l.title,
            "text": f"loot {l.loot_type}: {l.title}. {(l.content or '')[:300]}",
        })

    for c in db.query(Credential).filter(Credential.project_id == project_id).all():
        docs.append({
            "type": "credential", "id": c.id, "title": c.username or "(credential)",
            "text": f"credential type={c.cred_type} source={c.source} "
                    f"user={c.username or '-'} host={c.target_host or '-'}",
        })

    scans = (
        db.query(Scan)
        .join(Target, Scan.target_id == Target.id)
        .filter(Target.project_id == project_id)
        .all()
    )
    for s in scans:
        docs.append({
            "type": "scan", "id": s.id, "title": s.scan_type or "scan",
            "text": f"scan {s.scan_type} module={s.module} status={s.status}",
        })

    return docs


def retrieve(db: Session, project_id: str, question: str, k: int = 12) -> list[dict]:
    """Return the top-k documents most relevant to the question.

    Intent-aware: token overlap (stopwords removed) plus boosts when the question
    names a record type (e.g. "findings") or a severity (e.g. "critical"). Ties and
    the no-hit fallback break toward the most useful types so scan-status rows never
    crowd out findings/vulns.
    """
    docs = _gather(db, project_id)
    if not docs:
        return []

    q = _tokens(question)
    wanted_types = {_TYPE_HINTS[t] for t in q if t in _TYPE_HINTS}
    wanted_sev = {s for s in _SEVERITIES if s in q}

    scored: list[tuple[int, int, dict]] = []
    for d in docs:
        score = len(q & _tokens(d["text"] + " " + d["title"]))
        if d["type"] in wanted_types:
            score += 3
        if wanted_sev and any(s in d["text"].lower() for s in wanted_sev):
            score += 2
        scored.append((score, _TYPE_PRIORITY.get(d["type"], 0), d))

    scored.sort(key=lambda x: (-x[0], -x[1]))
    top = [d for score, _, d in scored if score > 0][:k]
    if top:
        return top

    # Nothing matched — return the most useful docs by type priority (findings first),
    # not raw insertion order, so an unmatched question doesn't surface scan noise.
    return [d for _, _, d in sorted(scored, key=lambda x: -x[1])][:k]


def build_messages(project_name: str, question: str, docs: list[dict]) -> list[dict]:
    """Assemble a grounded chat prompt from retrieved context."""
    if docs:
        counts: dict[str, int] = {}
        for d in docs:
            counts[d["type"]] = counts.get(d["type"], 0) + 1
        inventory = ", ".join(f"{n} {t}" for t, n in sorted(counts.items())) or "none"
        context = "\n".join(
            f"[{i + 1}] ({d['type']}) {d['text']}" for i, d in enumerate(docs)
        )
    else:
        inventory = "none"
        context = "(no engagement data found for this project yet)"

    system = (
        "You are Seraph's engagement analyst. Answer ONLY from the CONTEXT below, "
        "which is data from the current penetration-testing engagement. Each context "
        "line is tagged with its record type — finding, vuln, loot, credential, scan. "
        "A 'scan' line is only the status of a tool run; it is NOT a finding. "
        "If the user asks about a record type that is absent from the context, say so "
        "plainly (e.g. 'No findings have been recorded for this engagement yet') instead "
        "of describing unrelated records. Be concise, cite the bracketed source numbers "
        "(e.g. [2]) you actually used, and never invent findings or credentials."
    )
    user = (
        f"PROJECT: {project_name}\n"
        f"CONTEXT INVENTORY: {inventory}\n\n"
        f"CONTEXT:\n{context}\n\n"
        f"QUESTION: {question}"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def citations(docs: list[dict]) -> list[dict]:
    """Strip retrieved docs down to citation chips for the UI."""
    return [{"n": i + 1, "type": d["type"], "id": d["id"], "title": d["title"]}
            for i, d in enumerate(docs)]
