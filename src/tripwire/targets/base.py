from __future__ import annotations

from typing import Protocol


class Agent(Protocol):
    """The agent under test. Given a user prompt and a sandbox (its tools), return its answer."""
    def run(self, prompt: str, sandbox) -> str: ...
