"""Stdio MCP server that relays every message to a taintline bridge URL (gateway/bridge.py).

    python -m taintline.gateway.bridge_stdio http://127.0.0.1:PORT/mcp

For agents that only launch MCP servers as commands. It forwards to the one URL it was given and
nothing else, and only to a loopback address.
"""
from __future__ import annotations

import json
import sys
import threading
import urllib.request
from urllib.parse import urlparse

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def relay(url: str, line: str, timeout: float = 300.0) -> str | None:
    req = urllib.request.Request(url, line.encode(), method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Accept": "application/json, text/event-stream"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read()
    return body.decode() if r.status == 200 and body else None


_out = threading.Lock()


def _emit(text: str) -> None:
    with _out:
        sys.stdout.write(text.strip() + "\n")
        sys.stdout.flush()


def listen(url: str) -> None:
    """Relay the bridge's event stream (tools/list_changed notifications) to stdout, until it closes."""
    req = urllib.request.Request(url, method="GET", headers={"Accept": "text/event-stream"})
    try:
        with urllib.request.urlopen(req, timeout=None) as r:
            for raw in r:
                line = raw.decode().rstrip("\r\n")
                if line.startswith("data:"):
                    _emit(line[5:].strip())
    except Exception:                    # the bridge closed at the end of the trial
        pass


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1 or urlparse(argv[0]).hostname not in LOOPBACK:
        print("usage: python -m taintline.gateway.bridge_stdio http://127.0.0.1:PORT/mcp", file=sys.stderr)
        return 2
    url = argv[0]
    threading.Thread(target=listen, args=(url,), daemon=True).start()
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            out = relay(url, line)
        except Exception as e:           # answer the request so the client does not hang
            try:
                rid = json.loads(line).get("id")
            except ValueError:
                rid = None
            if rid is None:
                continue
            out = json.dumps({"jsonrpc": "2.0", "id": rid,
                              "error": {"code": -32603, "message": f"bridge unreachable: {e}"}})
        if out:
            _emit(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
