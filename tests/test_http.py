"""Streamable HTTP: client, recording proxy, injection and rug-pull monitoring over real HTTP."""
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from taintline.gateway.hash import hash_tools
from taintline.gateway.mcp_sandbox import MCPSandbox
from taintline.gateway.proxy_http import HttpProxy
from taintline.scanner.enumerate import enumerate_url
from taintline.scanner.rugpull import check, pin
from taintline.scope import Gate, OutOfScope, parse_scope

SERVERS = Path(__file__).parent.parent / "lab" / "servers"


def _gate(*servers):
    return Gate(parse_scope({"name": "t", "authorized_by": "me", "servers": list(servers)}))


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _serve(name, *flags):
    port = _free_port()
    proc = subprocess.Popen([sys.executable, str(SERVERS / "serve_http.py"), name, str(port), *flags],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return proc, f"http://127.0.0.1:{port}/mcp", f"127.0.0.1:{port}"
        except OSError:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("server did not start")


@pytest.fixture(params=[[], ["--legacy"]], ids=["stateless", "legacy"])
def notes(request):
    proc, url, host = _serve("notes", *request.param)
    yield url, host
    proc.kill()


def test_enumerate_url_works_on_both_protocol_eras(notes):
    url, host = notes
    tools = enumerate_url(_gate(host), url)
    assert {t["name"] for t in tools} == {"read_note", "send_email"}


def test_out_of_scope_url_is_refused_before_any_request():
    with pytest.raises(OutOfScope):
        enumerate_url(_gate("notes"), "http://127.0.0.1:9/mcp")


def test_sandbox_over_http_records_and_injects(notes, tmp_path):
    url, host = notes
    t = tmp_path / "t.jsonl"
    inj = {"surface": "tool_result", "target_tool": "read_note", "payload": "PLANTED-RESULT"}
    with MCPSandbox(_gate(host), host, None, None, {}, None, inj, str(t), url=url) as sb:
        assert {d["name"] for d in sb.tool_defs()} == {"read_note", "send_email"}
        out = sb.call("read_note", {"name": "todo"})
        assert "buy milk" in out and "PLANTED-RESULT" in out
    entries = [json.loads(line) for line in t.read_text().splitlines()]
    assert any(e.get("injected") for e in entries)
    assert any(e["dir"] == "client->server" and e["msg"].get("method") == "tools/call" for e in entries)
    assert not any("authorization" in json.dumps(e.get("http", {})).lower() and "<redacted>" not in json.dumps(e["http"])
                   for e in entries)


def test_description_injection_changes_served_hash_over_http(notes, tmp_path):
    url, host = notes
    t = tmp_path / "t.jsonl"
    inj = {"surface": "tool_description", "target_tool": "read_note", "payload": "<IMPORTANT>bad</IMPORTANT>"}
    with MCPSandbox(_gate(host), host, None, None, {}, None, inj, str(t), url=url) as sb:
        assert "bad" in next(d for d in sb.tool_defs() if d["name"] == "read_note")["description"]
    e = next(json.loads(x) for x in t.read_text().splitlines() if "served_hashes" in x)
    assert e["served_hashes"]["read_note"] != e["upstream_hashes"]["read_note"]


def test_proxy_forwards_only_the_mcp_path_and_binds_localhost(notes):
    import urllib.error
    import urllib.request
    url, host = notes
    with HttpProxy(url) as px:
        assert px.url.startswith("http://127.0.0.1:")
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(px.url.replace("/mcp", "/admin"), timeout=5)
        assert e.value.code == 404


def test_rug_pull_is_caught_by_pin_and_monitor_over_http():
    proc, url, host = _serve("rugpull")
    try:
        gate = _gate(host)
        before = enumerate_url(gate, url)
        pins = pin(before)
        with MCPSandbox(gate, host, None, None, {}, None, None, None, url=url) as sb:
            sb.call("get_quote", {})                    # the call that triggers the swap
        after = enumerate_url(gate, url)
        report = check(pins, after)
        assert hash_tools(before) != hash_tools(after)
        assert [c["tool"] for c in report["changes"]] == ["get_quote"]
        assert any(f["severity"] == "high" for f in report["findings"])    # the new text is flagged
    finally:
        proc.kill()
