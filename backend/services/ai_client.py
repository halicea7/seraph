"""
Thin wrapper around the OpenAI-compatible chat/completions API
supported by both Ollama (http://localhost:11434) and LMStudio (http://localhost:1234).
No external dependencies — uses stdlib urllib only.
"""
import json
import urllib.request
import urllib.error


def _base(endpoint: str) -> str:
    return endpoint.rstrip("/")


def load_llm_params(db) -> dict:
    """Read LLM generation parameters from AppSetting rows.

    Returns a dict of kwargs suitable for passing to chat_complete(**kwargs).
    Only includes keys whose values are actually stored (non-empty).
    """
    from database import AppSetting

    keys = {
        "temperature": float,
        "top_p": float,
        "top_k": int,
        "min_p": float,
        "presence_penalty": float,
        "repetition_penalty": float,
        "timeout": int,
    }
    params: dict = {}
    for name, cast in keys.items():
        row = db.query(AppSetting).filter(AppSetting.key == f"ai_{name}").first()
        if row and row.value != "":
            try:
                params[name] = cast(row.value)
            except (ValueError, TypeError):
                pass
    return params


def fetch_models(endpoint: str) -> list[str]:
    """Return model IDs from the /v1/models endpoint."""
    url = f"{_base(endpoint)}/v1/models"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
            return [m["id"] for m in data.get("data", [])]
    except Exception as exc:
        raise RuntimeError(f"Cannot reach LLM at {endpoint}: {exc}") from exc


def fetch_tool_capable_models(endpoint: str) -> list[str]:
    """Return only model IDs whose Ollama capabilities include 'tools'.

    Uses /api/tags to list models then /api/show per model.
    Falls back to returning all models if the endpoint is not Ollama-native.
    """
    base = _base(endpoint)
    tags_url = f"{base}/api/tags"
    try:
        with urllib.request.urlopen(tags_url, timeout=5) as resp:
            data = json.loads(resp.read())
            all_models: list[str] = [m["name"] for m in data.get("models", [])]
    except Exception:
        # Not a native Ollama endpoint — fall back to /v1/models with no filtering
        return fetch_models(endpoint)

    capable: list[str] = []
    for name in all_models:
        try:
            payload = json.dumps({"name": name}).encode()
            req = urllib.request.Request(
                f"{base}/api/show",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                info = json.loads(resp.read())
                caps: list[str] = info.get("capabilities", [])
                if "tools" in caps:
                    capable.append(name)
        except Exception:
            pass
    return capable


def chat_complete(
    endpoint: str,
    model: str,
    messages: list[dict],
    timeout: int = 300,
    temperature: float | None = None,
    top_p: float | None = None,
    top_k: int | None = None,
    min_p: float | None = None,
    presence_penalty: float | None = None,
    repetition_penalty: float | None = None,
) -> str:
    """Synchronous chat completion — returns the assistant message text."""
    url = f"{_base(endpoint)}/v1/chat/completions"
    body: dict = {"model": model, "messages": messages, "stream": False}
    if temperature is not None:
        body["temperature"] = temperature
    if top_p is not None:
        body["top_p"] = top_p
    if top_k is not None:
        body["top_k"] = top_k
    if min_p is not None:
        body["min_p"] = min_p
    if presence_penalty is not None:
        body["presence_penalty"] = presence_penalty
    if repetition_penalty is not None:
        body["repetition_penalty"] = repetition_penalty
    payload = json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
            return data["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        raise RuntimeError(f"LLM HTTP {exc.code}: {body}") from exc
    except Exception as exc:
        raise RuntimeError(f"LLM request failed: {exc}") from exc
