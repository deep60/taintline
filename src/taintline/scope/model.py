from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Scope:
    """What you are authorized to test. Default-deny: anything not listed is refused."""
    name: str
    authorized_by: str               # who gave permission (must be explicit)
    servers: tuple[str, ...]         # hostnames (or stdio server names) in scope
    tools: tuple[str, ...] | None = None   # None = every tool on in-scope servers
    fuzz: bool = False               # active probing (path traversal, SSRF...) allowed?
