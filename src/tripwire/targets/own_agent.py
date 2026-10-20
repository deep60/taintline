"""Your own agent: a plain tool-use loop against the Anthropic API.
Needs ANTHROPIC_API_KEY. UNTESTED against the live API (the loop logic is unit-tested
with a fake client)."""
from __future__ import annotations

DEFAULT_SYSTEM = "You are a helpful assistant with tool access."


class AgentTimeout(RuntimeError):
    """The agent never produced a final answer. Counted as an ERROR, not as a task failure."""


class AnthropicAgent:
    def __init__(self, model: str, system: str | None = None, max_turns: int = 8, client=None):
        self.model = model
        self.system = system or DEFAULT_SYSTEM
        self.max_turns = max_turns
        self._client = client            # injectable so the loop can be tested without the API

    def _get_client(self):
        if self._client is None:
            import anthropic

            self._client = anthropic.Anthropic()
        return self._client

    def run(self, prompt: str, sb) -> str:
        client = self._get_client()
        msgs = [{"role": "user", "content": prompt}]
        for _ in range(self.max_turns):
            resp = client.messages.create(
                model=self.model, max_tokens=1024, system=self.system,
                tools=sb.tool_defs(), messages=msgs,
            )
            msgs.append({"role": "assistant", "content": resp.content})
            uses = [b for b in resp.content if b.type == "tool_use"]
            if not uses:
                return "".join(b.text for b in resp.content if b.type == "text")
            msgs.append({"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": u.id, "content": sb.call(u.name, u.input)}
                for u in uses
            ]})
        raise AgentTimeout(f"no final answer after {self.max_turns} turns")