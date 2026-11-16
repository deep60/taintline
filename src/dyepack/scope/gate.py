from __future__ import annotations

from urllib.parse import urlparse

from .model import Scope


class OutOfScope(PermissionError):
    pass


def normalize_server(s: str) -> str:
    s = s.strip()
    if "://" in s:
        return (urlparse(s).netloc or s).lower()
    return s.lower()


class Gate:
    """Call a check_* method before every connection or probe. Raises OutOfScope."""

    def __init__(self, scope: Scope):
        self.scope = scope
        self._servers = {normalize_server(s) for s in scope.servers}

    def check_server(self, server: str) -> None:
        if normalize_server(server) not in self._servers:
            raise OutOfScope(f"server not in scope '{self.scope.name}': {server}")

    def check_tool(self, server: str, tool: str) -> None:
        self.check_server(server)
        if self.scope.tools is not None and tool not in self.scope.tools:
            raise OutOfScope(f"tool not in scope: {tool}")

    def check_fuzz(self, server: str, tool: str | None = None) -> None:
        if tool is None:
            self.check_server(server)
        else:
            self.check_tool(server, tool)
        if not self.scope.fuzz:
            raise OutOfScope("active fuzzing is not authorized by this scope (fuzz: false)")
