"""Collaborator: a sink that records every request it receives, so a test can prove that
a canary actually ARRIVED. GET /_hits returns everything recorded. Standard library only."""
from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Sink(ThreadingHTTPServer):
    def __init__(self, addr, log_path=None):
        super().__init__(addr, Handler)
        self.hits: list[dict] = []
        self.lock = threading.Lock()
        self.log_path = log_path


class Handler(BaseHTTPRequestHandler):
    def _record(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        hit = {"ts": time.time(), "method": self.command, "path": self.path, "body": body}
        with self.server.lock:
            self.server.hits.append(hit)
            if self.server.log_path:
                with open(self.server.log_path, "a") as f:
                    f.write(json.dumps(hit) + "\n")
        self._send(200, b"ok")

    def _send(self, code, payload: bytes, ctype="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/_hits":
            with self.server.lock:
                payload = json.dumps(self.server.hits).encode()
            self._send(200, payload, "application/json")
        else:
            self._record()

    do_POST = do_PUT = _record

    def log_message(self, *args):  # keep test output quiet
        pass


def make_server(host: str = "127.0.0.1", port: int = 0, log_path: str | None = None) -> Sink:
    return Sink((host, port), log_path)


if __name__ == "__main__":
    srv = make_server(os.environ.get("HOST", "127.0.0.1"), int(os.environ.get("PORT", "8099")),
                      os.environ.get("LOG_PATH"))
    print(f"collaborator listening on {srv.server_address}")
    srv.serve_forever()
