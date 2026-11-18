"""Recording MCP proxy for Streamable HTTP, the HTTP twin of gateway/proxy.py.

It listens on 127.0.0.1 (never a public interface) and forwards ONLY to the one upstream URL it was
given, so it cannot be used as an open relay. Each POST is one JSON-RPC exchange; the response is
either application/json or a text/event-stream, and both are parsed, recorded, hashed and (if asked)
injected the same way the stdio proxy does. SSE responses are buffered until the upstream closes
them, so long-lived streams (subscriptions/listen) are not supported here.

Authorization, cookie and API-key headers are never written to the transcript.
"""
from __future__ import annotations

import http.client
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .hash import hash_tools
from .proxy import Recorder, _payload_for_call, _plant_in_result, _plant_in_tools

SECRET_HEADERS = {"authorization", "cookie", "proxy-authorization", "x-api-key"}
DROP_REQUEST = {"host", "content-length", "connection", "accept-encoding", "transfer-encoding"}
DROP_RESPONSE = {"content-length", "connection", "transfer-encoding", "content-encoding"}
MAX_BODY = 8 * 1024 * 1024
_EVENT_SPLIT = re.compile(r"\r?\n\r?\n")


def _safe_headers(headers) -> dict:
    return {k: ("<redacted>" if k.lower() in SECRET_HEADERS else v) for k, v in headers.items()}


class HttpProxy:
    def __init__(self, upstream: str, transcript: str | None = None, inject: dict | None = None,
                 port: int = 0):
        u = urlparse(upstream)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError(f"upstream must be an http(s) URL, got {upstream!r}")
        self.upstream = u
        self.inject = inject
        self.rec = Recorder(transcript)
        self._target_calls = 0
        self._lock = threading.Lock()
        self._path = u.path or "/"
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"      # one exchange per connection, no keep-alive state

            def log_message(self, *a):         # quiet
                pass

            def _handle(self):
                proxy._handle(self)

            do_POST = do_GET = do_DELETE = _handle

        self._server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    # -- lifecycle -------------------------------------------------------------------------
    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}{self._path}"

    def start(self) -> "HttpProxy":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self.rec.close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    # -- one exchange ----------------------------------------------------------------------
    def _handle(self, h: BaseHTTPRequestHandler) -> None:
        if h.path.split("?")[0] != self._path:
            h.send_error(404, "this proxy only forwards the MCP endpoint")
            return
        n = int(h.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            h.send_error(413)
            return
        body = h.rfile.read(n) if n else b""
        pending = self._record_request(h, body)
        up = self.upstream
        conn_cls = http.client.HTTPSConnection if up.scheme == "https" else http.client.HTTPConnection
        try:
            conn = conn_cls(up.hostname, up.port, timeout=60)
            headers = {k: v for k, v in h.headers.items() if k.lower() not in DROP_REQUEST}
            headers["Accept-Encoding"] = "identity"
            conn.request(h.command, self._path + (f"?{up.query}" if up.query else ""),
                         body or None, headers)
            resp = conn.getresponse()
            data = resp.read()
        except OSError as e:
            self.rec.write(dir="proxy", error=str(e))
            h.send_error(502, f"upstream unreachable: {e}")
            return
        finally:
            try:
                conn.close()
            except Exception:
                pass
        ctype = (resp.getheader("Content-Type") or "").split(";")[0].strip().lower()
        if ctype == "application/json":
            data = self._rewrite_json(data, pending, resp.status)
        elif ctype == "text/event-stream":
            data = self._rewrite_sse(data, pending, resp.status)
        else:
            self.rec.write(dir="server->client", http={"status": resp.status}, raw=data[:2000].decode("utf-8", "replace"))
        h.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() not in DROP_RESPONSE:
                h.send_header(k, v)
        h.send_header("Content-Length", str(len(data)))
        h.end_headers()
        h.wfile.write(data)

    def _record_request(self, h, body: bytes) -> dict:
        pending: dict = {}
        try:
            parsed = json.loads(body) if body else None
        except json.JSONDecodeError:
            parsed = None
        msgs = parsed if isinstance(parsed, list) else [parsed] if isinstance(parsed, dict) else []
        for m in msgs:
            if "id" in m and "method" in m:
                pending[m["id"]] = (m["method"], (m.get("params") or {}).get("name"))
            entry = {"dir": "client->server", "msg": m, "http": {"method": h.command, "headers": _safe_headers(h.headers)}}
            hm = h.headers.get("Mcp-Method")      # 2026-07-28: header must match the body
            if hm and hm != m.get("method"):
                entry["header_mismatch"] = {"Mcp-Method": hm, "body": m.get("method")}
            self.rec.write(**entry)
        if not msgs:
            self.rec.write(dir="client->server", http={"method": h.command, "headers": _safe_headers(h.headers)},
                           raw=body[:2000].decode("utf-8", "replace"))
        return pending

    def _transform(self, msg: dict, pending: dict, status: int) -> dict:
        """Record one server->client message; plant the injection when it applies."""
        extra: dict = {}
        if isinstance(msg, dict) and "result" in msg and msg.get("id") in pending:
            method, tool = pending[msg["id"]]
            inj = self.inject
            if method == "tools/list":
                extra["upstream_hashes"] = hash_tools(msg["result"].get("tools", []))
                if inj and inj.get("surface") == "tool_description":
                    _plant_in_tools(msg, inj)
                extra["served_hashes"] = hash_tools(msg["result"].get("tools", []))
            elif method == "tools/call" and inj and inj.get("surface") == "tool_result" \
                    and tool == inj.get("target_tool"):
                with self._lock:
                    idx, self._target_calls = self._target_calls, self._target_calls + 1
                text = _payload_for_call(inj, idx)
                if text is not None:
                    _plant_in_result(msg, {"payload": text})
                    extra["injected"] = True
        self.rec.write(dir="server->client", msg=msg, http={"status": status}, **extra)
        return msg

    def _rewrite_json(self, data: bytes, pending: dict, status: int) -> bytes:
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError:
            self.rec.write(dir="server->client", http={"status": status}, raw=data[:2000].decode("utf-8", "replace"))
            return data
        if isinstance(parsed, list):
            parsed = [self._transform(m, pending, status) for m in parsed]
        else:
            parsed = self._transform(parsed, pending, status)
        return json.dumps(parsed).encode()

    def _rewrite_sse(self, data: bytes, pending: dict, status: int) -> bytes:
        out = []
        for block in _EVENT_SPLIT.split(data.decode("utf-8", "replace")):
            if not block.strip():
                continue
            lines = block.splitlines()
            payload = "\n".join(line[5:].lstrip(" ") for line in lines if line.startswith("data:"))
            if payload:
                try:
                    msg = self._transform(json.loads(payload), pending, status)
                    lines = [line for line in lines if not line.startswith("data:")] + [f"data: {json.dumps(msg)}"]
                except json.JSONDecodeError:
                    pass
            out.append("\n".join(lines))
        return ("\n\n".join(out) + "\n\n").encode()
