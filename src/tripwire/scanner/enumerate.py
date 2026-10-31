"""Tool inventory. Offline (from a saved manifest) works now; live enumeration needs the
Phase 1 MCP client."""
from __future__ import annotations

import json
from pathlib import Path

from ..gateway.hash import hash_tool


def load_tools(path: str | Path) -> list[dict]:
    data = json.loads(Path(path).read_text())
    return data["tools"] if isinstance(data, dict) else data


def inventory(tools: list[dict]) -> list[dict]:
    return [{"name": t.get("name"), "description": t.get("description", ""),
             "hash": hash_tool(t)} for t in tools]


def enumerate_server(gate, server_name: str, command: str, args: list[str] | None = None,
                     timeout: float = 30.0) -> list[dict]:
    """Live tools/list over stdio. Raises OutOfScope before any process is started."""
    import asyncio

    from ..gateway.client import connect

    async def go():
        async with connect(gate, server_name, command, args) as session:
            res = await session.list_tools()
            return [t.model_dump(by_alias=True, exclude_none=True) for t in res.tools]

    async def bounded():
        return await asyncio.wait_for(go(), timeout)

    return asyncio.run(bounded())


def enumerate_url(gate, url: str, timeout: float = 30.0, mode: str = "auto") -> list[dict]:
    """Live tools/list over Streamable HTTP. Raises OutOfScope before any request is sent."""
    import asyncio

    from ..gateway.client import connect_url

    async def go():
        async with connect_url(gate, url, mode) as client:
            res = await client.list_tools(cache_mode="bypass")
            return [t.model_dump(by_alias=True, exclude_none=True) for t in res.tools]

    async def bounded():
        return await asyncio.wait_for(go(), timeout)

    return asyncio.run(bounded())
