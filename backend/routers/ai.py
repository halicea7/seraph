from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from database import get_db, AppSetting, Project, Target, Scan, Finding
from services.ai_client import fetch_models, chat_complete, load_llm_params

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

    def _sev_rank(f: Finding) -> int:
        try:
            return SEVERITY_ORDER.index(f.severity)
        except ValueError:
            return 99

    top = sorted(findings, key=_sev_rank)[:30]
    findings_summary = "\n".join(
        f"- [{f.severity.upper()}] {f.title}: {(f.description or '')[:200]}"
        for f in top
    )

    target_names = ", ".join(t.hostname_or_ip for t in targets[:5])

    if req.style == "executive":
        prompt = (
            f"You are a senior cybersecurity analyst writing an executive summary for a security report.\n\n"
            f"Project: {project.name}\n"
            f"Targets assessed: {len(targets)} ({target_names})\n"
            f"Scans completed: {len(scans)}\n"
            f"Findings: {len(findings)} total — {sev_counts}\n\n"
            f"Top findings:\n{findings_summary}\n\n"
            f"Write a clear, professional executive summary (3–5 paragraphs). Start with an overall risk "
            f"posture, highlight the most critical issues, and close with remediation priority guidance. "
            f"Do not use bullet points in the summary itself."
        )
    else:
        prompt = (
            f"You are a penetration tester writing a technical report narrative.\n\n"
            f"Project: {project.name}\n"
            f"Targets: {', '.join(t.hostname_or_ip for t in targets[:10])}\n"
            f"Findings ({len(findings)} total):\n{findings_summary}\n\n"
            f"Write a detailed technical narrative covering: attack surface overview, key vulnerabilities "
            f"discovered, exploitation potential, and recommended remediation steps. Be specific and technical."
        )

    messages = [{"role": "user", "content": prompt}]
    try:
        narrative = chat_complete(endpoint, model, messages, **load_llm_params(db))
        return {"narrative": narrative}
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))
