import pytest

from taintline.scope import Gate, OutOfScope, ScopeError, parse_scope


def good(**kw):
    d = {"name": "t", "authorized_by": "me", "servers": ["localhost:8099", "lab.example"]}
    d.update(kw)
    return parse_scope(d)


def test_in_scope_server_passes_and_url_is_normalized():
    g = Gate(good())
    g.check_server("localhost:8099")
    g.check_server("http://LOCALHOST:8099/mcp")


def test_out_of_scope_server_refused():
    with pytest.raises(OutOfScope):
        Gate(good()).check_server("evil.example")


def test_tool_allowlist():
    g = Gate(good(tools=["read_file"]))
    g.check_tool("lab.example", "read_file")
    with pytest.raises(OutOfScope):
        g.check_tool("lab.example", "send_email")


def test_fuzz_requires_explicit_permission():
    with pytest.raises(OutOfScope):
        Gate(good()).check_fuzz("lab.example")
    Gate(good(fuzz=True)).check_fuzz("lab.example")
    with pytest.raises(OutOfScope):                  # fuzz on, but server not in scope
        Gate(good(fuzz=True)).check_fuzz("other.example")


@pytest.mark.parametrize("bad", [
    {"authorized_by": "me", "servers": ["a"]},                       # no name
    {"name": "t", "servers": ["a"]},                                 # no authorized_by
    {"name": "t", "authorized_by": " ", "servers": ["a"]},           # blank authorized_by
    {"name": "t", "authorized_by": "me", "servers": []},             # empty servers
    {"name": "t", "authorized_by": "me", "servers": ["*.example"]},  # wildcard
    {"name": "t", "authorized_by": "me", "servers": ["a"], "fuzz": "yes"},
    {"name": "t", "authorized_by": "me", "servers": ["a"], "extra": 1},
])
def test_invalid_scopes_rejected(bad):
    with pytest.raises(ScopeError):
        parse_scope(bad)