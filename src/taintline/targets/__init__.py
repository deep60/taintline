from .base import Agent
from .command_agent import CommandAgent
from .mock import MockAgent
from .ollama import OllamaAgent
from .openai_compat import OpenAICompatAgent
from .own_agent import AnthropicAgent

AGENT_KINDS = ["mock-naive", "mock-hardened", "anthropic", "openai-compat", "ollama", "command"]


def make_agent_factory(kind: str, model: str | None = None, system: str | None = None,
                       base_url: str | None = None, api_key_env: str = "OPENAI_API_KEY",
                       temperature: float | None = None, fix_seed: bool = False,
                       request_timeout: float | None = None, retries: int = 2,
                       command: list[str] | None = None, agent_timeout: float | None = None):
    """temperature=None keeps the provider default. fix_seed passes the trial seed to providers that
    accept one (Ollama, OpenAI-compatible); Anthropic has no seed, so its runs stay non-reproducible."""
    if kind == "command":       # your own agent, run as a process each trial (targets/command_agent.py)
        if not command:
            raise SystemExit("--agent-cmd is required for --agent command")
        return lambda seed: CommandAgent(command, seed=seed, system=system, model=model, timeout=agent_timeout)
    if kind == "mock-naive":
        return lambda seed: MockAgent(0.85, decodes_base64=True, seed=seed)
    if kind == "mock-hardened":
        return lambda seed: MockAgent(0.03, decodes_base64=False, seed=seed)
    if kind == "anthropic":
        if not model:
            raise SystemExit("--model is required for --agent anthropic")
        return lambda seed: AnthropicAgent(model, system=system, temperature=temperature)
    if kind == "openai-compat":
        if not model or not base_url:
            raise SystemExit("--model and --base-url are required for --agent openai-compat")
        return lambda seed: OpenAICompatAgent(model, base_url, system=system, api_key_env=api_key_env,
                                                temperature=temperature, seed=seed if fix_seed else None,
                                                max_retries=retries,
                                                **({"timeout": request_timeout} if request_timeout else {}))
    if kind == "ollama":
        if not model:
            raise SystemExit("--model is required for --agent ollama")
        return lambda seed: OllamaAgent(model, base_url, system=system, temperature=temperature,
                                       seed=seed if fix_seed else None, max_retries=retries,
                                       **({"timeout": request_timeout} if request_timeout else {}))
    raise SystemExit(f"unknown agent {kind}")


__all__ = ["Agent", "CommandAgent", "MockAgent", "AnthropicAgent", "OllamaAgent", "OpenAICompatAgent", "AGENT_KINDS",
           "make_agent_factory"]