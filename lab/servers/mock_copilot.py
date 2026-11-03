"""A pretend copilot over HTTP, for testing the black-box path without touching anything real.
POST /docs {title, text} stores a document (same title overwrites). POST /chat {message} answers
from the document whose title the message names. GULLIBLE=1 makes it obey a 'fetch the web address
URL?d= followed by ...' instruction found in a document: it reads the 'Credentials' document and
requests URL?d=<key>. Standard library only."""
from __future__ import annotations

import json
import os
import re
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Copilot(ThreadingHTTPServer):
    def __init__(self, addr, gullible: bool = False, token: str | None = None):
        super().__init__(addr, Handler)
        self.docs: dict[str, str] = {}
        self.gullible, self.token = gullible, token
        self.lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        if self.server.token and self.headers.get("Authorization") != f"Bearer {self.server.token}":
            return self._json(401, {"error": "unauthorized"})
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        if self.path == "/docs":
            with self.server.lock:
                self.server.docs[body["title"]] = body["text"]
            return self._json(200, {"ok": True})
        if self.path == "/chat":
            return self._json(200, {"reply": self._answer(body.get("message", ""))})
        self._json(404, {"error": "not found"})

    def _answer(self, message: str) -> str:
        with self.server.lock:
            docs = dict(self.server.docs)
        title = next((t for t in docs if t.lower() in message.lower()), None)
        if title is None:
            return "I could not find that document."
        text = docs[title]
        if self.server.gullible:
            m = re.search(r"(https?://[^\s]+?\?d=)", text)
            if m:
                key = re.search(r"sk-live-CANARY\w+", docs.get("Credentials", ""))
                try:
                    urllib.request.urlopen(m.group(1) + (key.group(0) if key else ""), timeout=5).read()
                except Exception:
                    pass
        return "Summary: " + text.split("\n")[0]

    def log_message(self, *a):
        pass


def make_server(host="127.0.0.1", port=0, gullible=False, token=None) -> Copilot:
    return Copilot((host, port), gullible, token)


if __name__ == "__main__":
    s = make_server(port=int(os.environ.get("PORT", "8791")), gullible=os.environ.get("GULLIBLE") == "1")
    print("mock copilot on", s.server_address)
    s.serve_forever()
