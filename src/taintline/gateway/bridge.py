"""Serve a sandbox's tools to an agent that runs in its own process, as a Streamable HTTP MCP server.

The agent under test connects here like it would to any MCP server. Every call goes through
sb.call(), so it lands in sb.calls and reaches the real lab server through the recording proxy,
exactly as calls from the built-in agents do; the oracle and the sink cannot tell the difference.

It listens on 127.0.0.1 only, on a free port, for the length of one trial. It is a test fixture,
not a gateway: one JSON response per POST, no server-initiated stream (GET answers 405, which the
spec allows), and only tools. Agents that speak stdio MCP use `stdio_command`, a shim
(gateway/bridge_stdio.py) that relays each line to this endpoint.
"""
from __future__ import annotations

import json
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .. import __version__

DEFAULT_PROTOCOL = "2025-06-18"
MAX_BODY = 8 * 1024 * 1024
METHOD_NOT_FOUND, INVALID_REQUEST, PARSE_ERROR = -32601, -32600, -32700


def _tool(d: dict) -> dict:
    return {"name": d["name"], "description": d.get("description", ""),
            "inputSchema": d.get("input_schema") or {"type": "object"}}


class McpBridge:
    def __init__(self, sandbox, host: str = "127.0.0.1"):
        self.sb = sandbox
        self._lock = threading.Lock()        # sandboxes record calls in order; keep them in order
        self._session = secrets.token_hex(8)
        self._srv = ThreadingHTTPServer((host, 0), self._handler())
        self._srv.daemon_threads = True
        self.url = f"http://{host}:{self._srv.server_address[1]}/mcp"
        self.stdio_command = [sys.executable, "-m", "taintline.gateway.bridge_stdio", self.url]
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)

    def __enter__(self) -> "McpBridge":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._srv.shutdown()
        self._srv.server_close()
        self._thread.join(timeout=5)

    # -- JSON-RPC ----------------------------------------------------------------------------
    def handle(self, msg: dict) -> dict:
        method, params = msg.get("method"), msg.get("params") or {}
        if method == "initialize":
            result = {"protocolVersion": params.get("protocolVersion") or DEFAULT_PROTOCOL,
                      "capabilities": {"tools": {"listChanged": False}},
                      "serverInfo": {"name": "taintline-bridge", "version": __version__}}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": [_tool(d) for d in self.sb.tool_defs()]}
        elif method == "tools/call":
            with self._lock:
                text = self.sb.call(params.get("name", ""), params.get("arguments") or {})
            result = {"content": [{"type": "text", "text": text}], "isError": text.startswith("error")}
        else:
            return {"jsonrpc": "2.0", "id": msg.get("id"),
                    "error": {"code": METHOD_NOT_FOUND, "message": f"method not found: {method}"}}
        return {"jsonrpc": "2.0", "id": msg.get("id"), "result": result}

    def _handler(self):
        bridge = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code: int, body: dict | None = None, extra: dict | None = None):
                data = json.dumps(body).encode() if body is not None else b""
                self.send_response(code)
                if body is not None:
                    self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Mcp-Session-Id", bridge._session)
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):                    # no server-initiated stream
                self._send(405, None, {"Allow": "POST, DELETE"})

            def do_DELETE(self):                 # session end: nothing to clean up
                self._send(200)

            def do_POST(self):
                if self.path.split("?")[0] != "/mcp":
                    return self._send(404)
                n = int(self.headers.get("Content-Length") or 0)
                if n > MAX_BODY:
                    return self._send(413)
                try:
                    msg = json.loads(self.rfile.read(n))
                except ValueError:
                    return self._send(400, {"jsonrpc": "2.0", "id": None,
                                            "error": {"code": PARSE_ERROR, "message": "invalid JSON"}})
                if not isinstance(msg, dict):
                    return self._send(400, {"jsonrpc": "2.0", "id": None,
                                            "error": {"code": INVALID_REQUEST, "message": "batches unsupported"}})
                if "id" not in msg or "method" not in msg:   # a notification or a response: accepted
                    return self._send(202)
                self._send(200, bridge.handle(msg))

        return H
