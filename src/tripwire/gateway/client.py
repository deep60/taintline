"""MCP client (stdio + Streamable HTTP). PHASE 1: not implemented.

Read the current MCP spec first (2026-07-28 removed the initialize handshake and
sessions) and support both it and 2025-11-25. Every connection must pass scope.Gate.
"""


def connect(*args, **kwargs):
    raise NotImplementedError("Phase 1: real MCP client")
