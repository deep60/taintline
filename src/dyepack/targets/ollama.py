"""Agent for a local Ollama server using its NATIVE /api/chat endpoint (tool calling is
reported to be more reliable there than on the OpenAI-compatible /v1 path).
Free, runs entirely on your machine. UNTESTED against a live Ollama; the loop is
unit-tested with a fake HTTP client."""
from __future__ import annotations

import json

from .http_retry import post_json
from .openai_compat import to_openai_tools
from .own_agent import DEFAULT_SYSTEM, AgentTimeout

DEFAULT_URL = "http://localhost:11434"


class OllamaAgent:
    def __init__(self, model: str, base_url: str | None = None, system: str | None = None,
                 max_turns: int = 8, timeout: float = 300.0, client=None,
                 temperature: float | None = None, seed: int | None = None,
                 max_retries: int = 2, backoff: float = 2.0):
        self.model = model
        self.base_url = (base_url or DEFAULT_URL).rstrip("/")
        self.system = system or DEFAULT_SYSTEM
        self.max_turns = max_turns
        self.timeout = timeout           # generous: the first call loads the model into memory
        self.max_retries, self.backoff, self.retries = max_retries, backoff, 0
        self._client = client            # injectable so the loop can be tested without Ollama
        self.tokens_used = 0
        self.options = {k: v for k, v in (("temperature", temperature), ("seed", seed)) if v is not None}

    def _http(self):
        if self._client is None:
            import httpx

            self._client = httpx.Client(timeout=self.timeout)
        return self._client

    def _post(self, payload: dict) -> dict:
        return post_json(self, f"{self.base_url}/api/chat", payload)

    @staticmethod
    def _args(raw) -> dict:
        if isinstance(raw, str):                 # some builds return a JSON string, others an object
            try:
                raw = json.loads(raw or "{}")
            except json.JSONDecodeError:
                return {}
        return raw if isinstance(raw, dict) else {}

    def run(self, prompt: str, sb) -> str:
        msgs = [{"role": "system", "content": self.system}, {"role": "user", "content": prompt}]
        tools = to_openai_tools(sb.tool_defs())
        for _ in range(self.max_turns):
            resp = self._post({"model": self.model, "messages": msgs, "tools": tools, "stream": False,
                                **({"options": self.options} if self.options else {})})
            self.tokens_used += (resp.get("prompt_eval_count") or 0) + (resp.get("eval_count") or 0)
            msg = resp["message"]
            calls = msg.get("tool_calls") or []
            if not calls:
                return msg.get("content") or ""
            msgs.append({"role": "assistant", "content": msg.get("content") or "", "tool_calls": calls})
            for c in calls:
                fn = c["function"]
                result = sb.call(fn["name"], self._args(fn.get("arguments")))
                msgs.append({"role": "tool", "tool_name": fn["name"], "content": result})
        raise AgentTimeout(f"no final answer after {self.max_turns} turns")