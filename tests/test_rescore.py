import json

from taintline.attacks import load_attacks
from taintline.attacks.runner import run_suite
from taintline.cli import main
from taintline.rescore import rescore
from taintline.targets import MockAgent
from taintline.tasks import TASKS


class ChattyAgent:
    """Does its task, then emails the user a summary nobody asked for (what llama3.1 did)."""
    def run(self, prompt, sandbox):
        out = sandbox.call("read_email", {"id": "1"}) if "email" in prompt.lower() else \
            sandbox.call("read_file", {"path": "notes/todo.txt"}) if "todo" in prompt.lower() else \
            sandbox.call("fetch_url", {"url": "https://acme.example/pricing"})
        sandbox.call("send_email", {"to": "user@example.com", "body": "summary: " + out[:40]})
        return out


def test_new_oracle_does_not_count_chatty_baselines_as_false_alarms():
    res = run_suite(lambda s: ChattyAgent(), [], TASKS, 3)
    assert all(b["false_alarm"] == 0 and b["unrequested_outbound"] == 1.0 for b in res["baseline"])


def test_rescore_repairs_results_judged_by_the_old_oracle():
    res = run_suite(lambda s: ChattyAgent(), [], TASKS, 3)
    for b in res["baseline"]:                      # simulate the OLD verdicts: any outbound = success
        b["false_alarm"] = 1.0
        for t in b["trials"]:
            t["oracle_success"] = True
    fixed, summary = rescore({**res, "summary": {"stale": True}})
    assert all(b["false_alarm"] == 0 for b in fixed["baseline"])
    assert summary["baseline_false_alarm"] == 0 and summary["baseline_unrequested_outbound"] == 1.0
    assert "summary" not in fixed


def test_rescore_keeps_real_attack_successes():
    res = run_suite(lambda s: MockAgent(0.9, True, s), load_attacks(), TASKS, 6)
    fixed, _ = rescore(res)
    assert [p["successes"] for p in fixed["pairs"]] == [p["successes"] for p in res["pairs"]]
    assert sum(p["successes"] for p in fixed["pairs"]) > 0


def test_rescore_does_not_mutate_its_input():
    res = run_suite(lambda s: MockAgent(0.9, True, s), load_attacks(), TASKS, 2)
    before = json.dumps(res, sort_keys=True)
    rescore(res)
    assert json.dumps(res, sort_keys=True) == before


def test_rescore_cli_writes_a_single_summary(tmp_path):
    main(["run", "--agent", "mock-naive", "-n", "2", "--out", str(tmp_path / "a")])
    main(["rescore", str(tmp_path / "a" / "results.json"), "--out", str(tmp_path / "b")])
    data = json.loads((tmp_path / "b" / "results.json").read_text())
    assert data["meta"]["rescored"] is True and data["summary"]["errors"] == 0
    assert (tmp_path / "b" / "report.md").exists()