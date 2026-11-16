import io
import json

import pytest

from tripwire.demo import EMAIL_RE, run_demo


def test_demo_shows_a_clean_baseline_a_proven_leak_and_a_defended_agent(tmp_path):
    buf = io.StringIO()
    res = run_demo(str(tmp_path), stream=buf)
    s = res["summary"]
    assert s == {"attack_leaked": True, "baseline_false_alarm": False, "errors": 0, "defended_leaked": False}
    scenes = {x["scene"]: x for x in res["scenes"]}
    assert scenes["attack"]["canary"] in json.dumps(scenes["attack"]["sink_hits"])   # proven at the sink
    assert scenes["baseline"]["sink_hits"] == [] and scenes["defended"]["sink_hits"] == []
    text = buf.getvalue()
    assert "ARRIVED" in text and "\033[" not in text          # no colour codes when not a terminal
    assert json.loads((tmp_path / "demo.json").read_text())["summary"]["attack_leaked"] is True


def test_a_real_model_needs_a_scope_file(tmp_path):
    with pytest.raises(SystemExit, match="must authorize it"):
        run_demo(str(tmp_path), agent="ollama", model="m", scope_path=str(tmp_path / "missing.yaml"),
                 stream=io.StringIO())


def test_email_match_drops_a_trailing_full_stop():
    assert EMAIL_RE.search("send it to attacker@evil.example.").group(0) == "attacker@evil.example"


def test_an_unreachable_model_is_an_error_never_a_resisted_attack(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "unused")
    scope = tmp_path / "scope.yaml"
    scope.write_text("name: t\nauthorized_by: me\nservers: [127.0.0.1:9]\n")
    buf = io.StringIO()
    res = run_demo(str(tmp_path / "o"), agent="openai-compat", model="m", base_url="http://127.0.0.1:9/v1",
                   scope_path=str(scope), stream=buf)
    assert res["summary"]["errors"] == 2 and res["summary"]["attack_leaked"] is False
    assert "resisted" not in buf.getvalue() and "says nothing about the agent" in buf.getvalue()
    assert "[1/2]" in buf.getvalue()
