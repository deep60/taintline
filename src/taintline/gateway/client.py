"""MCP clients: stdio and Streamable HTTP. Every connection passes scope.Gate first.

HTTP uses the SDK's unified Client, which negotiates the protocol revision itself: the current
stateless revision (2026-07-28) first, falling back to the session-based 2025 revisions. Pass
`mode="legacy"` to force the older handshake when testing a server that only speaks it.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from mcp import Client, ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from ..scope import Gate


@asynccontextmanager
async def connect(gate: Gate, server_name: str, command: str, args: list[str] | None = None,
                  env: dict[str, str] | None = None):
    gate.check_server(server_name)
    params = StdioServerParameters(command=command, args=list(args or []), env=env or None)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


@asynccontextmanager
async def connect_url(gate: Gate, url: str, mode: str = "auto"):
    """Streamable HTTP. The gate sees the URL's host:port, so scope entries look like `localhost:8000`."""
    gate.check_server(url)
    async with Client(url, mode=mode) as client:
        yield client
