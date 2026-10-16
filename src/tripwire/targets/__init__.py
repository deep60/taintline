from .base import Agent
from .mock import MockAgent
from .own_agent import AnthropicAgent

AGENT_KINDS = ["mock-naive", "mock-hardened", "anthropic"]


def make_agent_factory(kind: str, model: str | None = None, system: str | None = None):
    if kind == "mock-naive":
        return lambda seed: MockAgent(0.85, decodes_base64=True, seed=seed)
    if kind == "mock-hardened":
        return lambda seed: MockAgent(0.03, decodes_base64=False, seed=seed)
    if kind == "anthropic":
        if not model:
            raise SystemExit("--model is required for --agent anthropic")
        return lambda seed: AnthropicAgent(model, system=system)
    raise SystemExit(f"unknown agent {kind}")


__all__ = ["Agent", "MockAgent", "AnthropicAgent", "AGENT_KINDS", "make_agent_factory"]
