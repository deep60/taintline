"""audit: the lethal trifecta across the servers one client loads, and a 'prove it' command per finding."""
import json
from pathlib import Path

from taintline.report.sarif import from_audit
from taintline.scanner import scan_manifest
from taintline.scanner.config_audit import audit, format_audit
from taintline.scanner.server_catalog import identify

FS = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/Users/me/docs"]}
FETCH = {"command": "uvx", "args": ["mcp-server-fetch==0.6.2"]}
BRAVE = {"command": "npx", "args": ["-y", "@brave/brave-search-mcp-server@2.0.0"]}
SMTP = {"command": "npx", "args": ["-y", "smtp-mcp@1.2.0"]}
GITHUB = {"url": "https://api.githubcopilot.com/mcp/"}


def _audit(tmp_path, servers, name="mcp.json", top="mcpServers"):
    p = tmp_path / name
    p.write_text(json.dumps({top: servers} if top else servers, indent=2))
    return audit([str(p)])


def _kind(res, kind):
    return [f for f in res["findings"] if f["kind"] == kind]


def test_trifecta_across_servers_is_found_with_its_legs(tmp_path):
    res = _audit(tmp_path, {"files": FS, "search": BRAVE, "mailer": SMTP})
    [f] = _kind(res, "lethal_trifecta_across_servers")
    assert f["server"] == "files, mailer, search" and f["severity"] == "medium"
    assert "private data (files)" in f["message"] and "a way out (mailer)" in f["message"]
    assert f["prove"]["command"] == "taintline session start --lab files+inbox"


def test_web_only_way_out_is_proven_with_the_web_lab(tmp_path):
    [f] = _kind(_audit(tmp_path, {"files": FS, "fetch": FETCH}), "lethal_trifecta_across_servers")
    assert f["prove"]["command"] == "taintline session start --lab db+web"


def test_two_legs_are_not_a_trifecta(tmp_path):
    res = _audit(tmp_path, {"files": FS, "search": BRAVE})
    assert not [f for f in res["findings"] if f["kind"].startswith("lethal_trifecta")]


def test_one_server_with_all_three_is_reported_alone(tmp_path):
    res = _audit(tmp_path, {"github": GITHUB, "files": FS})
    [f] = _kind(res, "lethal_trifecta_in_server")
    assert f["server"] == "github" and "code host" in f["message"]
    assert not _kind(res, "lethal_trifecta_across_servers")


def test_unknown_servers_and_paths_are_never_guessed():
    assert identify("mystuff", {"command": "node", "args": ["/opt/x/index.js"]}) is None
    assert identify("tool", {"command": "node", "args": ["/Users/me/db/server.js"]}) is None
    assert identify("anything", FS)[0] == {"private_read"}


def test_disabled_servers_do_not_count(tmp_path):
    res = _audit(tmp_path, {"files": FS, "search": BRAVE, "mailer": {**SMTP, "disabled": True}})
    assert not _kind(res, "lethal_trifecta_across_servers")


def test_claude_code_project_servers_combine_with_global_ones(tmp_path):
    doc = {"mcpServers": {"files": FS}, "projects": {"/work/app": {"mcpServers": {"fetch": FETCH}}}}
    res = _audit(tmp_path, doc, name=".claude.json", top=None)
    [f] = _kind(res, "lethal_trifecta_across_servers")
    assert f["server"] == "fetch, files"


def test_prove_commands_on_other_findings(tmp_path):
    res = _audit(tmp_path, {"files": {"command": "npx", "args": ["-y", "some-server"],
                                      "env": {"API_KEY": "sk-abcdefghijklmnopqrstuv"}}})
    unpinned = _kind(res, "unpinned_package")[0]
    assert unpinned["prove"]["command"] == f"taintline monitor --config {unpinned['file']}"
    assert _kind(res, "secret_in_config")[0]["prove"] is None      # a fact needs no proof
    text = format_audit(res, color=False)
    assert "prove: taintline monitor --config" in text


def test_sarif_carries_the_prove_command(tmp_path):
    res = _audit(tmp_path, {"files": FS, "fetch": FETCH})
    f = next(x for x in from_audit(res) if x.rule == "config/lethal_trifecta_across_servers")
    assert f.props["prove"] == "taintline session start --lab db+web" and "Prove:" in f.message


def test_every_prove_command_names_a_real_lab_and_attack():
    import shlex

    from taintline.labs import get_lab
    from taintline.scanner.prove import PROOF
    for cmd, _ in PROOF.values():
        argv = shlex.split(cmd)
        if "--lab" in argv:
            lab = get_lab(argv[argv.index("--lab") + 1])
            if "--attack" in argv:
                assert argv[argv.index("--attack") + 1] in {a.id for a in lab.attacks()}, cmd


def test_manifest_scan_findings_get_prove_commands():
    poisoned = json.loads((Path(__file__).parents[1] / "examples" / "poisoned_manifest.json").read_text())
    res = scan_manifest(poisoned)
    by_kind = {f["kind"]: f["prove"] for f in res["findings"]}
    assert by_kind["hidden_directive_tag"]["command"].endswith("--lab poisoned+inbox --attack native_poison")
    assert next(v for k, v in by_kind.items() if k.startswith("duplicate"))["command"].endswith("shadow+inbox")
