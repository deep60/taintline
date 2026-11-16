import json
from pathlib import Path

from dyepack.sandbox import BASE_TOOLS
from dyepack.scanner import scan_manifest
from dyepack.scanner.auth_checks import check_client_config
from dyepack.scanner.toxic_flow import analyze
from dyepack.scoring import trifecta

POISONED = Path(__file__).parents[1] / "examples" / "poisoned_manifest.json"


def test_sandbox_toolset_has_complete_trifecta():
    assert all(trifecta([t["name"] for t in BASE_TOOLS]).values())


def test_trifecta_incomplete_without_egress():
    tools = [t["name"] for t in BASE_TOOLS if t["name"] in {"read_file", "fetch_url"}]
    assert not all(trifecta(tools).values())


def test_manifest_toxic_flow_detection():
    tools = [
        {"name": "read_notes", "description": "Read private notes"},
        {"name": "fetch_page", "description": "Fetch a web page"},
        {"name": "send_message", "description": "Send a message to anyone"},
    ]
    assert analyze(tools)["trifecta_complete"]
    assert not analyze(tools[:2])["trifecta_complete"]


def test_scanner_flags_poisoning_and_shadowing():
    kinds = {f["kind"] for f in scan_manifest(json.loads(POISONED.read_text()))["findings"]}
    assert {"hidden_directive_tag", "concealment_from_user"} <= kinds
    assert any("duplicate" in k for k in kinds)


def test_scanner_quiet_on_benign_tool():
    assert scan_manifest([{"name": "get_weather", "description": "Get weather for a city."}])["findings"] == []


def test_hidden_unicode_flagged():
    m = [{"name": "x", "description": "Add numbers.\u200b\u200b"}]
    assert any(f["kind"] == "hidden_unicode" for f in scan_manifest(m)["findings"])


def test_config_check_finds_secret_and_http_without_echoing():
    cfg = {"mcpServers": {
        "a": {"command": "x", "env": {"KEY": "sk-abcdefghijklmnopqrstuv"}},
        "b": {"url": "http://remote.example/mcp"},
        "c": {"url": "http://localhost:8000/mcp"},
        "d": {"command": "x", "env": {"KEY": "${KEY}"}},
    }}
    found = check_client_config(cfg)
    kinds = {(f["server"], f["kind"]) for f in found}
    assert ("a", "secret_in_config:api_key_like") in kinds
    assert ("b", "insecure_transport") in kinds
    assert not any(f["server"] in {"c", "d"} for f in found)
    assert "abcdefghij" not in json.dumps(found)