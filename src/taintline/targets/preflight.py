"""Ask the model server one cheap question before trial 1, so a dead endpoint stops the run at once.

Without this, a run against a server that isn't running spends every trial on retries and ends as
hundreds of errors (an invalid run, but only after minutes of waiting). The check lists the models
the server offers: it costs no tokens, and it catches the next most common mistake too, a model
that isn't loaded or is misspelled.

Call it only after the scope gate has approved the same host (`check_run`): it contacts the run's
own model server and nothing else. Hosted APIs (Anthropic) and the in-process mock agents are skipped."""
from __future__ import annotations

import os

from .ollama import DEFAULT_URL as OLLAMA_URL

CHECKED_AGENTS = {"openai-compat", "ollama"}


class EndpointUnavailable(RuntimeError):
    pass


def _models_url(kind: str, base_url: str | None) -> str:
    if kind == "ollama":
        return f"{(base_url or OLLAMA_URL).rstrip('/')}/api/tags"
    return f"{base_url.rstrip('/')}/models"


def _served(kind: str, body: dict) -> list[str]:
    if kind == "ollama":
        return [m.get("name") or m.get("model") or "" for m in body.get("models") or []]
    return [m.get("id", "") for m in body.get("data") or []]


def _matches(kind: str, model: str, served: list[str]) -> bool:
    if model in served:
        return True
    return kind == "ollama" and ":" not in model and f"{model}:latest" in served


def check_endpoint(kind: str, model: str | None, base_url: str | None,
                   api_key_env: str = "OPENAI_API_KEY", timeout: float = 10.0, client=None) -> str | None:
    """Raise EndpointUnavailable if the server doesn't answer or doesn't offer `model`.
    Returns a warning string when the server can't list models (the run then goes ahead), else None."""
    if kind not in CHECKED_AGENTS:
        return None
    import httpx

    url = _models_url(kind, base_url)
    headers = {}
    key = os.environ.get(api_key_env) if kind == "openai-compat" else None
    if key:
        headers["Authorization"] = f"Bearer {key}"
    http = client or httpx.Client(timeout=timeout)
    try:
        r = http.get(url, headers=headers)
    except httpx.TimeoutException:
        raise EndpointUnavailable(f"the model server at {url} did not answer within {timeout:g}s")
    except httpx.TransportError as e:
        hint = ("start it (LM Studio: Developer tab > Start Server; Ollama: `ollama serve`) "
                "and check the port in --base-url")
        raise EndpointUnavailable(f"nothing is answering at {url} ({type(e).__name__}: {e}). "
                                  f"Is the model server running? {hint}")
    finally:
        if client is None:
            http.close()
    status = getattr(r, "status_code", 200)
    if status in (404, 405, 501):
        return f"{url} returned HTTP {status}, so the model list can't be checked; going ahead"
    if status in (401, 403):
        raise EndpointUnavailable(f"{url} refused the request (HTTP {status}): check the key in ${api_key_env}")
    if status >= 400:
        raise EndpointUnavailable(f"{url} returned HTTP {status}")
    try:
        served = [s for s in _served(kind, r.json()) if s]
    except ValueError:
        return f"{url} did not return JSON, so the model list can't be checked; going ahead"
    if not served:
        raise EndpointUnavailable(f"the server at {url} is running but offers no models: load {model} first")
    if model and not _matches(kind, model, served):
        shown = ", ".join(served[:10]) + (" ..." if len(served) > 10 else "")
        raise EndpointUnavailable(f"the server at {url} doesn't offer {model!r}. It offers: {shown}")
    return None
