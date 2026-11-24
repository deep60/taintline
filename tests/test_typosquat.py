"""Look-alike MCP package names: flagged when close to a well-known one, quiet on the real ones."""
import json

import pytest

from taintline.scanner.config_audit import audit
from taintline.scanner.typosquat import KNOWN, distance, look_alike


@pytest.mark.parametrize("spec,eco,kind", [
    ("@modelcontextprotocal/server-filesystem@1.0.0", "npm", "possible_typosquat"),    # look-alike scope
    ("@modelcontextprotoco1/server-filesystem", "npm", "possible_typosquat"),          # homoglyph scope
    ("server-filesystem", "npm", "scope_confusion"),                                   # scope missing
    ("mcp-server-fecth==0.6.2", "pypi", "possible_typosquat"),                         # swapped letters
    ("firecrawl-mpc", "npm", "possible_typosquat"),
])
def test_look_alikes_are_flagged(spec, eco, kind):
    hit = look_alike(spec, eco)
    assert hit and hit[0] == kind, hit


@pytest.mark.parametrize("spec,eco", [
    *[(k + ("@1.0.0" if eco == "npm" else "==1.0"), eco) for eco, names in KNOWN.items() for k in names],
    ("@modelcontextprotocol/server-aws-kb-retrieval", "npm"),   # same official scope: can't be a squat
    ("@modelcontextprotocol/server-filesytem@1.0.0", "npm"),    # a typo in an owned scope just 404s
    ("@acme/internal-notes-mcp@2.1.0", "npm"),                  # unrelated name
    ("mcp-server-kubernetes==1.0", "pypi"),
    ("anything", "docker"),                                     # no list for this ecosystem
])
def test_real_and_unrelated_packages_are_quiet(spec, eco):
    assert look_alike(spec, eco) is None


def test_distance_counts_a_swap_as_one():
    assert distance("fetch", "fecth") == 1 and distance("abc", "abc") == 0 and distance("", "ab") == 2


def test_audit_reports_it_high(tmp_path):
    p = tmp_path / "mcp.json"
    p.write_text(json.dumps({"mcpServers": {"fs": {"command": "npx", "args": [
        "-y", "@modelcontextprotocal/server-filesystem@1.0.0", "/tmp/x"]}}}))
    [f] = [f for f in audit([str(p)])["findings"] if f["kind"] == "possible_typosquat"]
    assert f["severity"] == "high" and "server-filesystem" in f["message"] and f["prove"] is None
