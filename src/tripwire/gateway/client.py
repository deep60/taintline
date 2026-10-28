"""MCP client (stdio). Every connection passes scope.Gate first.

Streamable HTTP is not implemented yet.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from ..scope import Gate


@asynccontextmanager
async def connect(gate: Gate, server_name: str, command: str, args: list[str] | None = None):
    gate.check_server(server_name)
    params = StdioServerParameters(command=command, args=list(args or []))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session
