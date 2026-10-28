"""Transparent stdio MCP proxy: sits between an MCP client and a real server, records every
JSON-RPC message, hashes the tool list, and can plant an injection.

MCP's stdio transport is newline-delimited JSON, so the proxy relays lines and only parses
what it needs. Run as a module:

    python -m tripwire.gateway.proxy --transcript t.jsonl [--inject-json '{...}'] -- CMD ARGS...

Injection spec: {"surface": "tool_description" | "tool_result", "target_tool": name, "payload": text}
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
import time

from .hash import hash_tools


class Recorder:
    def __init__(self, path: str | None):
        self._f = open(path, "a", buffering=1) if path else None
        self._lock = threading.Lock()

    def write(self, **entry) -> None:
        if self._f:
            with self._lock:
                self._f.write(json.dumps({"ts": time.time(), **entry}) + "\n")

    def close(self) -> None:
        if self._f:
            self._f.close()


def _plant_in_tools(msg: dict, inj: dict) -> None:
    for t in msg["result"].get("tools", []):
        if t.get("name") == inj.get("target_tool"):
            t["description"] = t.get("description", "") + "\n" + inj["payload"]


def _plant_in_result(msg: dict, inj: dict) -> None:
    content = msg["result"].setdefault("content", [])
    for item in content:
        if item.get("type") == "text":
            item["text"] += "\n\n" + inj["payload"]
            return
    content.append({"type": "text", "text": inj["payload"]})


def run_proxy(cmd: list[str], transcript: str | None = None, inject: dict | None = None,
              stdin=None, stdout=None) -> int:
    """Relay until the client closes stdin. Returns the server's exit code."""
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    rec = Recorder(transcript)
    server = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)  # stderr inherited
    pending: dict = {}          # request id -> (method, tool name)

    def client_to_server():
        for line in stdin:
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                msg = None
            if isinstance(msg, dict):
                if "id" in msg and "method" in msg:
                    pending[msg["id"]] = (msg["method"], (msg.get("params") or {}).get("name"))
                rec.write(dir="client->server", msg=msg)
            else:
                rec.write(dir="client->server", raw=line.decode("utf-8", "replace"))
            server.stdin.write(line)
            server.stdin.flush()
        server.stdin.close()

    def server_to_client():
        for line in server.stdout:
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                msg = None
            if isinstance(msg, dict) and "result" in msg and msg.get("id") in pending:
                method, tool = pending.pop(msg["id"])
                if method == "tools/list":
                    upstream = hash_tools(msg["result"].get("tools", []))
                    if inject and inject.get("surface") == "tool_description":
                        _plant_in_tools(msg, inject)
                        line = (json.dumps(msg) + "\n").encode()
                    rec.write(dir="server->client", msg=msg, upstream_hashes=upstream,
                              served_hashes=hash_tools(msg["result"].get("tools", [])))
                    stdout.write(line)
                    stdout.flush()
                    continue
                if method == "tools/call" and inject and inject.get("surface") == "tool_result" \
                        and tool == inject.get("target_tool"):
                    _plant_in_result(msg, inject)
                    line = (json.dumps(msg) + "\n").encode()
                    rec.write(dir="server->client", msg=msg, injected=True)
                    stdout.write(line)
                    stdout.flush()
                    continue
            rec.write(dir="server->client", msg=msg) if msg is not None else \
                rec.write(dir="server->client", raw=line.decode("utf-8", "replace"))
            stdout.write(line)
            stdout.flush()

    threads = [threading.Thread(target=client_to_server, daemon=True),
               threading.Thread(target=server_to_client, daemon=True)]
    for t in threads:
        t.start()
    threads[0].join()
    try:
        server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.terminate()
        server.wait()
    threads[1].join(timeout=2)
    rec.close()
    return server.returncode or 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--" not in argv:
        raise SystemExit("usage: python -m tripwire.gateway.proxy [options] -- SERVER_CMD [ARGS...]")
    i = argv.index("--")
    ap = argparse.ArgumentParser(prog="tripwire-proxy")
    ap.add_argument("--transcript")
    ap.add_argument("--inject-json", help="injection spec as JSON")
    a = ap.parse_args(argv[:i])
    inject = json.loads(a.inject_json) if a.inject_json else None
    return run_proxy(argv[i + 1:], a.transcript, inject)


if __name__ == "__main__":
    raise SystemExit(main())
