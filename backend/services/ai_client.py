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


def fetch_models(endpoint: str) -> list[str]:
    """Return model IDs from the /v1/models endpoint."""
    url = f"{_base(endpoint)}/v1/models"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
            return [m["id"] for m in data.get("data", [])]
    except Exception as exc:
        raise RuntimeError(f"Cannot reach LLM at {endpoint}: {exc}") from exc


def chat_complete(endpoint: str, model: str, messages: list[dict], timeout: int = 120) -> str:
    """Synchronous chat completion — returns the assistant message text."""
    url = f"{_base(endpoint)}/v1/chat/completions"
    payload = json.dumps({"model": model, "messages": messages, "stream": False}).encode()
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
