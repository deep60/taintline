"""Tool capability detection: right on every lab server's real tools, and quiet where the old
substring regexes fired ('http' in a description, 'note' in any tool)."""
import sys
from pathlib import Path

import pytest

from taintline.scanner.enumerate import enumerate_server
from taintline.scanner.toxic_flow import analyze, capabilities, explain
from taintline.scope import Gate, parse_scope

SERVERS = Path(__file__).parents[1] / "lab" / "servers"
PRIV, UNTR, OUT = "private_read", "untrusted_in", "external_out"

EXPECTED = {
    "notes": {"read_note": {PRIV}, "send_email": {OUT}},
    "inbox": {"list_emails": {PRIV, UNTR}, "read_email": {PRIV, UNTR}, "send_email": {OUT}},
    "web": {"fetch_url": {UNTR, OUT}, "http_post": {OUT}},
    "files": {"list_files": {PRIV}, "read_file": {PRIV}},
    "db": {"list_tables": {PRIV}, "query": {PRIV}},
    "browser": {"open_page": {UNTR, OUT}, "click_link": {UNTR}, "submit_form": {OUT}, "read_storage": {PRIV}},
    "poisoned": {"get_weather": set(), "convert_units": set()},
    "shadow": {"send_email": {OUT}},
}


@pytest.mark.parametrize("server", sorted(EXPECTED))
def test_lab_server_tools_are_classified(server):
    gate = Gate(parse_scope({"name": "t", "authorized_by": "me", "servers": [server]}))
    tools = enumerate_server(gate, server, sys.executable, [str(SERVERS / f"{server}_server.py")], 30)
    got = {t["name"]: capabilities(t) for t in tools}
    assert got == EXPECTED[server]


def test_lab_trifectas():
    def tools(*specs):
        return [{"name": n, "inputSchema": {"type": "object", "properties": {p: {} for p in ps}}}
                for n, ps in specs]
    inbox = tools(("list_emails", []), ("read_email", ["id"]), ("send_email", ["to", "body"]))
    assert analyze(inbox)["trifecta_complete"]
    assert analyze(inbox)["evidence"]["external_out"] == ["send_email"]
    assert not analyze(tools(("read_note", ["name"]), ("send_email", ["to", "body"])))["trifecta_complete"]


@pytest.mark.parametrize("tool", [
    {"name": "get_weather", "description": "Get the weather from the national weather HTTP API."},
    {"name": "create_note", "description": "Create a note with a title."},
    {"name": "format_date", "description": "Format a date; never posts or uploads anything."},
    {"name": "add", "description": "Add two numbers.", "inputSchema": {"properties": {"a": {}, "b": {}}}},
])
def test_no_capability_from_incidental_words(tool):
    assert capabilities(tool) == set(), explain(tool)


@pytest.mark.parametrize("tool,caps", [
    ({"name": "readEmail"}, {PRIV, UNTR}),                                     # camelCase
    ({"name": "get_post"}, {UNTR}),                                         # 'post' as a noun
    ({"name": "post_comment", "inputSchema": {"properties": {"issue": {}, "body": {}}}}, {OUT}),
    ({"name": "notify", "inputSchema": {"properties": {"channel": {}, "text": {}}}}, {OUT}),
    ({"name": "run", "inputSchema": {"properties": {"sql": {}}}}, {PRIV}),   # schema says what the name doesn't
    ({"name": "do_it", "description": "Send the report to an email address."}, {OUT}),   # description fallback
])
def test_names_schemas_and_fallback(tool, caps):
    assert capabilities(tool) == caps, explain(tool)


def test_every_capability_comes_with_a_reason():
    why = explain({"name": "fetch_url", "inputSchema": {"properties": {"url": {}}}})
    assert set(why) == {UNTR, OUT} and all(why.values())
