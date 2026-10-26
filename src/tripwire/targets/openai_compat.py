"""Agent for any OpenAI-compatible chat-completions API (OpenAI, Ollama, vLLM, LM Studio, and
many hosted providers). Uses httpx directly, so there is no extra dependency.
UNTESTED against live APIs; the loop is unit-tested with a fake HTTP client."""
from __future__ import annotations

import json
import os

from .own_agent import DEFAULT_SYSTEM, AgentTimeout


def to_openai_tools(tool_defs: list[dict]) -> list[dict]:
    return [{"type": "function",
             "function": {"name": d["name"], "description": d["description"],
                          "parameters": d["input_schema"]}} for d in tool_defs]


class OpenAICompatAgent:
    def __init__(self, model: str, base_url: str, system: str | None = None,
                 api_key_env: str = "OPENAI_API_KEY", max_turns: int = 8,
                 timeout: float = 120.0, client=None):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.system = system or DEFAULT_SYSTEM
        self.api_key_env = api_key_env
        self.max_turns = max_turns
        self.timeout = timeout
        self._client = client            # injectable so the loop can be tested without a network

    def _http(self):
        if self._client is None:
            import httpx

            self._client = httpx.Client(timeout=self.timeout)
        return self._client

    def _post(self, payload: dict) -> dict:
        headers = {"Content-Type": "application/json"}
        key = os.environ.get(self.api_key_env)
        if key:                          # local servers (e.g. Ollama) need no key
            headers["Authorization"] = f"Bearer {key}"
        r = self._http().post(f"{self.base_url}/chat/completions", json=payload, headers=headers)
        r.raise_for_status()
        return r.json()

    def run(self, prompt: str, sb) -> str:
        msgs = [{"role": "system", "content": self.system}, {"role": "user", "content": prompt}]
        tools = to_openai_tools(sb.tool_defs())
        for _ in range(self.max_turns):
            msg = self._post({"model": self.model, "messages": msgs, "tools": tools})["choices"][0]["message"]
            calls = msg.get("tool_calls") or []
            if not calls:
                return msg.get("content") or ""
            # rebuild the assistant message: some servers reject extra fields such as "refusal"
            msgs.append({"role": "assistant", "content": msg.get("content"), "tool_calls": calls})
            for c in calls:
                fn = c["function"]
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                result = sb.call(fn["name"], args if isinstance(args, dict) else {})
                msgs.append({"role": "tool", "tool_call_id": c["id"], "content": result})
        raise AgentTimeout(f"no final answer after {self.max_turns} turns")