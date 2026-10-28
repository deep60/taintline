"""A Sandbox look-alike backed by a REAL stdio MCP server, reached through the recording proxy.

Agents and oracles only need tool_defs(), call(), .calls and .canaries, so the existing
agents and evaluate() work against it unchanged.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import threading

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from ..sandbox import ToolCall
from ..scope import Gate


class MCPSandbox:
    def __init__(self, gate: Gate, server_name: str, command: str, args: list[str] | None = None,
                 canaries: dict | None = None, env: dict | None = None, inject: dict | None = None,
                 transcript: str | None = None, timeout: float = 30.0):
        gate.check_server(server_name)               # before anything is spawned
        self.canaries = dict(canaries or {})
        self.injection = inject
        self.calls: list[ToolCall] = []
        self._timeout = timeout
        proxy_args = ["-m", "tripwire.gateway.proxy"]
        if transcript:
            proxy_args += ["--transcript", transcript]
        if inject:
            proxy_args += ["--inject-json", json.dumps(inject)]
        proxy_args += ["--", command, *(args or [])]
        self._params = StdioServerParameters(command=sys.executable, args=proxy_args,
                                             env={**os.environ, **(env or {})})
        self._defs: list[dict] = []
        self._session = None
        self._error: BaseException | None = None
        self._ready = threading.Event()
        self._stop: asyncio.Event | None = None
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)

    # -- lifecycle -----------------------------------------------------------------------
    def start(self) -> "MCPSandbox":
        self._thread.start()
        self._main_future = asyncio.run_coroutine_threadsafe(self._main(), self._loop)
        if not self._ready.wait(self._timeout):
            self.close()
            raise TimeoutError("MCP server did not become ready")
        if self._error:
            self.close()
            raise self._error
        return self

    async def _main(self):
        self._stop = asyncio.Event()
        try:
            async with stdio_client(self._params) as (r, w):
                async with ClientSession(r, w) as s:
                    await s.initialize()
                    tools = (await s.list_tools()).tools
                    self._defs = [{"name": t.name, "description": t.description or "",
                                   "input_schema": t.input_schema} for t in tools]
                    self._session = s
                    self._ready.set()
                    await self._stop.wait()
        except BaseException as e:      # surfaced to start()/call()
            self._error = e
            self._ready.set()

    def close(self) -> None:
        if self._stop is not None:
            self._loop.call_soon_threadsafe(self._stop.set)
        fut = getattr(self, "_main_future", None)
        if fut is not None:
            try:
                fut.result(timeout=10)
            except Exception:
                pass
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.close()

    # -- Sandbox interface -----------------------------------------------------------------
    def tool_defs(self) -> list[dict]:
        return [dict(d) for d in self._defs]

    def call(self, name: str, args: dict) -> str:
        args = dict(args or {})
        try:
            fut = asyncio.run_coroutine_threadsafe(self._session.call_tool(name, args), self._loop)
            res = fut.result(timeout=self._timeout)
            text = "\n".join(getattr(c, "text", "") for c in res.content)
            if getattr(res, "is_error", False):
                text = f"error: {text}"
        except Exception as e:
            text = f"error: {e}"
        self.calls.append(ToolCall(name, args, text))
        return text
