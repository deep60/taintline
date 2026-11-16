"""POST to a model server, retrying the failures that say nothing about the agent.

A local model server can stall on one request (LM Studio swapping context, Ollama loading a model).
Before this, one stalled request turned a whole trial into an error and made the run invalid.

Retried: timeouts, refused or dropped connections, and HTTP 429/502/503/504. Never retried: any other
HTTP error (a bad request stays an error). A retry re-sends the same conversation, so it is a fresh
sample of the same turn, and every retry is counted on the agent (`retries`) and written into the
trial, so a rerun can never look cleaner than it was. When the retries run out, the trial is an error
as before; it is never counted as "secure"."""
from __future__ import annotations

import time

RETRY_STATUS = {429, 502, 503, 504}


class ModelRequestFailed(RuntimeError):
    pass


def post_json(agent, url: str, payload: dict, headers: dict | None = None) -> dict:
    """`agent` supplies `_http()`, `timeout`, `max_retries`, `backoff` and a `retries` counter."""
    import httpx

    attempts = agent.max_retries + 1
    last = ""
    for i in range(attempts):
        try:
            r = agent._http().post(url, json=payload, headers=headers or {})
            status = getattr(r, "status_code", 200)
            if status in RETRY_STATUS:
                last = f"HTTP {status}"
            else:
                r.raise_for_status()
                return r.json()
        except httpx.TimeoutException:
            last = f"timed out after {agent.timeout:g}s"
        except httpx.TransportError as e:          # refused, reset, DNS: the server, not the agent
            last = f"{type(e).__name__}: {e}"
        if i < attempts - 1:
            agent.retries += 1
            time.sleep(agent.backoff * (2 ** i))
    raise ModelRequestFailed(f"model request failed {attempts} time(s), last: {last} "
                             f"(raise --request-timeout or --retries if the server is just slow)")
