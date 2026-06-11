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


def _tokens(text: str | None) -> set[str]:
    return {w.lower() for w in _WORD.findall(text or "")}


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
    """Return the top-k documents most relevant to the question by token overlap."""
    docs = _gather(db, project_id)
    q = _tokens(question)
    scored = sorted(
        ((len(q & _tokens(d["text"] + " " + d["title"])), d) for d in docs),
        key=lambda x: -x[0],
    )
    top = [d for score, d in scored if score > 0][:k]
    # No keyword hits → fall back to the first k docs so the model still has context.
    return top or docs[:k]


def build_messages(project_name: str, question: str, docs: list[dict]) -> list[dict]:
    """Assemble a grounded chat prompt from retrieved context."""
    if docs:
        context = "\n".join(
            f"[{i + 1}] ({d['type']}) {d['text']}" for i, d in enumerate(docs)
        )
    else:
        context = "(no engagement data found for this project yet)"

    system = (
        "You are Seraph's engagement analyst. Answer ONLY from the CONTEXT below, "
        "which is data from the current penetration-testing engagement. If the answer "
        "is not in the context, say so plainly. Be concise and cite the bracketed "
        "source numbers (e.g. [2]) you used. Never invent findings or credentials."
    )
    user = f"PROJECT: {project_name}\n\nCONTEXT:\n{context}\n\nQUESTION: {question}"
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def citations(docs: list[dict]) -> list[dict]:
    """Strip retrieved docs down to citation chips for the UI."""
    return [{"n": i + 1, "type": d["type"], "id": d["id"], "title": d["title"]}
            for i, d in enumerate(docs)]
