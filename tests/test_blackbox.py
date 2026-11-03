import sys
import threading
from pathlib import Path

import pytest

root = Path(__file__).parent.parent
sys.path.insert(0, str(root / "lab" / "collaborator"))
sys.path.insert(0, str(root / "lab" / "servers"))

import mock_copilot  # noqa: E402
from server import make_server  # noqa: E402

from tripwire.blackbox import blackbox_attacks, blackbox_suite  # noqa: E402
from tripwire.scope import Gate, OutOfScope, parse_scope  # noqa: E402
from tripwire.targets.blackbox_http import BlackboxConfigError, load_config, parse_config  # noqa: E402


def _serve(srv):
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"127.0.0.1:{srv.server_address[1]}"


def _gate(*hosts):
    return Gate(parse_scope({"name": "t", "authorized_by": "me", "servers": list(hosts)}))


def _cfg(copilot_host, token="tok"):
    cfg = load_config(root / "examples" / "blackbox.example.yaml", expand_env=False)
    for ep in (cfg.chat, cfg.plant):
        ep.url = ep.url.replace("127.0.0.1:8791", copilot_host)
        ep.headers = {"Authorization": f"Bearer {token}"}
    cfg.delay_seconds = 0
    return cfg


@pytest.fixture
def world():
    sink = make_server()
    s_host = _serve(sink)
    made = []

    def start(gullible):
        c = mock_copilot.make_server(gullible=gullible, token="tok")
        made.append(c)
        return _serve(c)
    yield f"http://{s_host}", s_host, start
    sink.shutdown()
    for c in made:
        c.shutdown()


def test_gullible_copilot_leaks_and_the_sink_confirms(world, tmp_path):
    url, s_host, start = world
    c_host = start(True)
    attacks = [a for a in blackbox_attacks(url) if a.id == "direct_notice"]
    res = blackbox_suite(_gate(c_host, s_host), _cfg(c_host), url, 2, str(tmp_path), attacks)
    pair = res["pairs"][0]
    assert pair["delivered"] == pair["n"] and pair["fired"] == pair["n"]
    assert res["summary"]["baseline_false_alarm"] == 0 and res["summary"]["baseline_utility"] == 1.0
    assert res["summary"]["valid"] and res["target_kind"] == "blackbox_http"


def test_resistant_copilot_is_clean(world, tmp_path):
    url, s_host, start = world
    c_host = start(False)
    attacks = [a for a in blackbox_attacks(url) if a.id == "direct_notice"]
    res = blackbox_suite(_gate(c_host, s_host), _cfg(c_host), url, 2, str(tmp_path), attacks)
    assert res["pairs"][0]["delivered"] == 0 and res["summary"]["valid"]


def test_out_of_scope_target_is_refused_before_any_request(world, tmp_path):
    url, s_host, start = world
    c_host = start(True)
    with pytest.raises(OutOfScope):
        blackbox_suite(_gate(s_host), _cfg(c_host), url, 1, str(tmp_path), [])


def test_errors_are_counted_and_invalidate_the_run(world, tmp_path):
    url, s_host, start = world
    c_host = start(True)
    res = blackbox_suite(_gate(c_host, s_host), _cfg(c_host, token="wrong"), url, 1, str(tmp_path),
                         [a for a in blackbox_attacks(url) if a.id == "direct_notice"])
    assert res["overall"]["errors"] > 0 and not res["summary"]["valid"]


def test_request_budget_stops_the_run_and_marks_it_invalid(world, tmp_path):
    url, s_host, start = world
    c_host = start(True)
    res = blackbox_suite(_gate(c_host, s_host), _cfg(c_host), url, 3, str(tmp_path),
                         [a for a in blackbox_attacks(url) if a.id == "direct_notice"], max_requests=3)
    assert res["budget"]["stopped_by"] and not res["summary"]["valid"]


def test_attacks_aim_at_the_reachable_sink_not_the_fake_attacker_host(world):
    url, _, _ = world
    payloads = " ".join(a.payload for a in blackbox_attacks(url))
    assert url + "/collect" in payloads and "evil.example" not in payloads


def test_config_validation_and_env_secrets(monkeypatch):
    base = {"name": "x", "chat": {"url": "http://h/chat", "headers": {"Authorization": "Bearer ${T}"}},
            "tasks": [{"id": "t", "prompt": "p", "keywords": ["k"], "title": "T", "benign_text": "b"}]}
    with pytest.raises(BlackboxConfigError, match="T is not set"):
        parse_config(base)
    monkeypatch.setenv("T", "abc")
    assert parse_config(base).chat.headers["Authorization"] == "Bearer abc"
    with pytest.raises(BlackboxConfigError):
        parse_config({**base, "chat": {"url": "ftp://h"}})
    with pytest.raises(BlackboxConfigError):
        parse_config({**base, "tasks": []})
