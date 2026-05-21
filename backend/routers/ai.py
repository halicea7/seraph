from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from database import get_db, AppSetting, Project, Target, Scan, Finding
from services.ai_client import fetch_models, fetch_tool_capable_models, chat_complete, load_llm_params

router = APIRouter(prefix="/ai", tags=["ai"])

DEFAULT_ENDPOINT = "http://localhost:11434"
DEFAULT_MODEL = ""


def _get(db: Session, key: str, default: str = "") -> str:
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    return row.value if row else default


def _set(db: Session, key: str, value: str):
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(AppSetting(key=key, value=value))
    db.commit()


@router.get("/config")
def get_ai_config(db: Session = Depends(get_db)):
    def _getf(key, default):
        v = _get(db, key, "")
        try:
            return float(v) if v != "" else default
        except ValueError:
            return default

    def _geti(key, default):
        v = _get(db, key, "")
        try:
            return int(v) if v != "" else default
        except ValueError:
            return default

    return {
        "endpoint": _get(db, "ai_endpoint", DEFAULT_ENDPOINT),
        "model": _get(db, "ai_model", DEFAULT_MODEL),
        "provider": _get(db, "ai_provider", "ollama"),
        "temperature": _getf("ai_temperature", None),
        "top_p": _getf("ai_top_p", None),
        "top_k": _geti("ai_top_k", None),
        "min_p": _getf("ai_min_p", None),
        "presence_penalty": _getf("ai_presence_penalty", None),
        "repetition_penalty": _getf("ai_repetition_penalty", None),
        "timeout": _geti("ai_timeout", None),
    }


class AIConfigRequest(BaseModel):
    endpoint: str
    model: str
    provider: str = "ollama"
    temperature: Optional[float] = None
    top_p: Optional[float] = None
    top_k: Optional[int] = None
    min_p: Optional[float] = None
    presence_penalty: Optional[float] = None
    repetition_penalty: Optional[float] = None
    timeout: Optional[int] = None


@router.put("/config")
def save_ai_config(req: AIConfigRequest, db: Session = Depends(get_db)):
    _set(db, "ai_endpoint", req.endpoint.strip())
    _set(db, "ai_model", req.model.strip())
    _set(db, "ai_provider", req.provider.strip())

    def _save_optional(key, val):
        _set(db, key, "" if val is None else str(val))

    _save_optional("ai_temperature", req.temperature)
    _save_optional("ai_top_p", req.top_p)
    _save_optional("ai_top_k", req.top_k)
    _save_optional("ai_min_p", req.min_p)
    _save_optional("ai_presence_penalty", req.presence_penalty)
    _save_optional("ai_repetition_penalty", req.repetition_penalty)
    _save_optional("ai_timeout", req.timeout)
    return {"ok": True}


@router.get("/status")
def ai_status(db: Session = Depends(get_db)):
    endpoint = _get(db, "ai_endpoint", DEFAULT_ENDPOINT)
    try:
        models = fetch_models(endpoint)
        return {"online": True, "endpoint": endpoint, "model_count": len(models)}
    except Exception as exc:
        return {"online": False, "endpoint": endpoint, "error": str(exc)}


@router.get("/models")
def list_models(db: Session = Depends(get_db)):
    endpoint = _get(db, "ai_endpoint", DEFAULT_ENDPOINT)
    try:
        models = fetch_models(endpoint)
        return {"models": models}
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))


@router.get("/tool-models")
def list_tool_capable_models(db: Session = Depends(get_db)):
    """Return only models that support tool/function calling."""
    endpoint = _get(db, "ai_endpoint", DEFAULT_ENDPOINT)
    try:
        models = fetch_tool_capable_models(endpoint)
        return {"models": models}
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class NarrateRequest(BaseModel):
    project_id: str
    style: str = "executive"  # executive | technical


@router.post("/narrate")
def narrate_report(req: NarrateRequest, db: Session = Depends(get_db)):
    endpoint = _get(db, "ai_endpoint", DEFAULT_ENDPOINT)
    model = _get(db, "ai_model", DEFAULT_MODEL)
    if not model:
        raise HTTPException(400, "No AI model configured. Go to Settings → AI to set one.")

    project = db.query(Project).filter(Project.id == req.project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")

    targets = db.query(Target).filter(Target.project_id == req.project_id).all()
    target_ids = [t.id for t in targets]
    scans = db.query(Scan).filter(Scan.target_id.in_(target_ids)).all() if target_ids else []
    scan_ids = [s.id for s in scans]
    findings = db.query(Finding).filter(Finding.scan_id.in_(scan_ids)).all() if scan_ids else []

    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    def _sev_rank_str(s: str) -> int:
        try:
            return SEVERITY_ORDER.index(s)
        except ValueError:
            return 99

    def _sev_rank(f: Finding) -> int:
        return _sev_rank_str(f.severity)

    sorted_findings = sorted(findings, key=_sev_rank)

    def _finding_block(f: Finding) -> str:
        lines = [f"- [{f.severity.upper()}] {f.title}"]
        if f.cve_id:
            lines.append(f"  CVE: {f.cve_id}" + (f" | CVSS: {f.cvss_score}" if f.cvss_score else ""))
        if f.framework and f.control_id:
            lines.append(f"  Control: {f.framework} {f.control_id}")
        if f.tags:
            fw_tags = [t for t in f.tags.split(",") if t.startswith(("OWASP:", "MITRE:", "PCI:"))]
            if fw_tags:
                lines.append(f"  Tags: {', '.join(fw_tags)}")
        if f.description:
            lines.append(f"  Description: {f.description[:250]}")
        if f.remediation:
            lines.append(f"  Remediation: {f.remediation[:200]}")
        return "\n".join(lines)

    findings_block = "\n".join(_finding_block(f) for f in sorted_findings[:40]) or "No findings recorded."

    target_lines = "\n".join(
        f"- {t.hostname_or_ip} [{t.target_type.replace('_', ' ')}]"
        + (f" ports: {t.ports}" if t.ports else "")
        for t in targets
    )

    scan_types = sorted({s.scan_type for s in scans if s.scan_type})
    sev_summary = " | ".join(
        f"{k.upper()}: {v}" for k, v in sorted(sev_counts.items(), key=lambda x: _sev_rank_str(x[0])) if v
    ) or "none"

    data_block = f"""\
Project: {project.name}
Targets ({len(targets)}):
{target_lines}
Scans: {len(scans)} completed | Types: {', '.join(scan_types) if scan_types else 'various'}
Findings: {len(findings)} total | {sev_summary}

{findings_block}"""

    if req.style == "executive":
        system_msg = """\
You are a senior cybersecurity consultant writing a client-facing executive report.
Your audience is non-technical C-suite leadership.
Rules:
- Use ONLY the data provided. Do NOT invent findings, scores, CVEs, or details not in the data.
- Use Markdown: ## headings, **bold** for emphasis, bullet lists.
- Write in a professional, measured tone.
- Output exactly these four sections and nothing else:

## Executive Summary
2-3 paragraphs. What was assessed, the headline risk verdict, and why it matters to the business.

## Key Findings
Bullet list of the most significant issues (critical and high only). One sentence per finding in plain English — what it is and why it matters. If there are no critical/high findings, state that.

## Business Impact
2-3 sentences on realistic consequences if the findings were exploited (data breach, compliance exposure, downtime). Be factual, not alarmist.

## Recommended Actions
Three numbered tiers:
1. **Immediate (48 h)** — urgent mitigations
2. **Short-term (30 days)** — remediation tasks
3. **Ongoing** — process improvements"""

        user_msg = f"Write the executive report using this assessment data:\n\n{data_block}"

    else:
        system_msg = """\
You are a penetration tester writing the technical narrative for a security assessment report.
Your audience is the client's security and engineering teams.
Rules:
- Use ONLY the data provided. Do NOT invent CVE IDs, CVSS scores, services, or findings not listed below.
- If a CVE or CVSS is not in the data, do not mention one.
- Use Markdown: ## headings, ### sub-headings, **bold** for key terms, `code` for CVEs and commands, bullet lists.
- Output exactly these four sections and nothing else:

## Scope & Targets
List each assessed target, its type, and the scan types run against it.

## Findings by Severity
Group under ### Critical / ### High / ### Medium / ### Low / ### Info sub-headings (skip empty groups).
For each finding: what it is, which target it affects, CVE/CVSS only if provided in the data, any OWASP/MITRE/PCI tags from the data, and a remediation note.

## Attack Chains & Exploitation Potential
Based strictly on the findings above, describe realistic attack paths an adversary could take. If findings are minor, say so honestly.

## Remediation Roadmap
- **Immediate** — critical issues to fix within 48 h
- **Short-term** — high/medium issues within 30 days
- **Ongoing** — architectural and process improvements"""

        user_msg = f"Write the technical narrative using this assessment data:\n\n{data_block}"

    messages = [{"role": "system", "content": system_msg}, {"role": "user", "content": user_msg}]
    try:
        narrative = chat_complete(endpoint, model, messages, **load_llm_params(db))
        # Auto-save
        _set(db, f"ai_narrative_{req.project_id}_{req.style}", narrative)
        _set(db, f"ai_narrative_{req.project_id}_{req.style}_at", datetime.utcnow().isoformat())
        return {"narrative": narrative}
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))


class ChatRequest(BaseModel):
    messages: list[dict]
    model: Optional[str] = None


def _attack_context_block(messages: list[dict]) -> str:
    """Search ATT&CK index based on the last user message and return a formatted context block."""
    try:
        from services.attack_index import search as atk_search, get_status
        if get_status().get("count", 0) == 0:
            return ""
        last_user = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                content = m.get("content", "")
                last_user = content if isinstance(content, str) else " ".join(
                    p.get("text", "") for p in content if isinstance(p, dict)
                )
                break
        if len(last_user.strip()) < 5:
            return ""
        results = atk_search(last_user.strip(), limit=4)
        if not results:
            return ""
        lines = ["[MITRE ATT&CK — relevant techniques for this query]"]
        for t in results:
            lines.append(f"\n{t['technique_id']}: {t['name']}  |  tactic: {t['tactic']}")
            if t["description"]:
                lines.append(f"  {t['description'][:280]}")
            if t["detection"]:
                lines.append(f"  Detection hint: {t['detection'][:180]}")
        return "\n".join(lines)
    except Exception:
        return ""


def _inject_attack_context(messages: list[dict], context: str) -> list[dict]:
    if not context:
        return messages
    msgs = list(messages)
    for i, m in enumerate(msgs):
        if m.get("role") == "system":
            msgs[i] = {**m, "content": m["content"] + f"\n\n{context}"}
            return msgs
    return [{"role": "system", "content": context}] + msgs


@router.post("/chat")
def ai_chat(req: ChatRequest, db: Session = Depends(get_db)):
    """Generic LLM chat — used by the AI Operator for arbitrary message sequences."""
    endpoint = _get(db, "ai_endpoint", DEFAULT_ENDPOINT)
    model = req.model or _get(db, "ai_model", DEFAULT_MODEL)
    if not model:
        raise HTTPException(400, "No AI model configured. Go to Settings → AI to set one.")
    context = _attack_context_block(req.messages)
    messages = _inject_attack_context(req.messages, context)
    try:
        content = chat_complete(endpoint, model, messages, **load_llm_params(db))
        return {"content": content}
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))


@router.get("/narrate/{project_id}")
def get_saved_narratives(project_id: str, db: Session = Depends(get_db)):
    """Return previously saved narratives for a project."""
    result = {}
    for style in ("executive", "technical"):
        content = _get(db, f"ai_narrative_{project_id}_{style}", "")
        generated_at = _get(db, f"ai_narrative_{project_id}_{style}_at", "")
        if content:
            result[style] = {"content": content, "generated_at": generated_at}
    return result
