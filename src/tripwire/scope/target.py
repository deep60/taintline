from __future__ import annotations

from urllib.parse import urlparse

from .gate import Gate

HERMETIC_AGENTS = {"mock-naive", "mock-hardened"}   # in-process, never touch the network

_FIXED_HOSTS = {"anthropic": "api.anthropic.com"}
_OLLAMA_DEFAULT = "localhost:11434"


def target_server(agent: str, base_url: str | None) -> str | None:
    """The host:port a run will contact, or None for hermetic agents."""
    if agent in HERMETIC_AGENTS:
        return None
    if agent in _FIXED_HOSTS:
        return _FIXED_HOSTS[agent]
    if base_url:
        return urlparse(base_url).netloc.lower()
    if agent == "ollama":
        return _OLLAMA_DEFAULT
    raise ValueError(f"cannot determine target server for agent {agent!r}")


def check_run(gate: Gate | None, agent: str, base_url: str | None) -> str | None:
    """Raise OutOfScope unless the run's target is authorized. Hermetic agents need no scope."""
    server = target_server(agent, base_url)
    if server is None:
        return None
    if gate is None:
        from .gate import OutOfScope
        raise OutOfScope(f"agent '{agent}' contacts {server}: a SCOPE.yaml is required (see SCOPE.example.yaml)")
    gate.check_server(server)
    return server
