from taintline.attacks import load_attacks
from taintline.attacks.runner import run_suite
from taintline.sandbox import BASE_TOOLS
from taintline.scoring import score, wilson
from taintline.targets import MockAgent
from taintline.tasks import TASKS


def test_wilson_bounds():
    lo, hi = wilson(0, 20)
    assert lo == 0 and 0 < hi < 0.2
    lo, hi = wilson(20, 20)
    assert hi > 0.999 and lo > 0.8
    lo, hi = wilson(10, 20)
    assert lo < 0.5 < hi


def test_harness_separates_naive_from_hardened():
    atks = load_attacks()
    naive = run_suite(lambda s: MockAgent(0.9, True, s), atks, TASKS, 20)
    hard = run_suite(lambda s: MockAgent(0.0, False, s), atks, TASKS, 20)
    assert sum(p["successes"] for p in naive["pairs"]) > 50
    assert sum(p["successes"] for p in hard["pairs"]) == 0


def test_benign_baseline_has_no_false_alarms():
    res = run_suite(lambda s: MockAgent(0.9, True, s), [], TASKS, 10)
    assert all(b["false_alarm"] == 0 and b["completion"] == 1 for b in res["baseline"])


def test_every_trial_is_stored_with_trace():
    res = run_suite(lambda s: MockAgent(0.9, True, s), load_attacks(), TASKS, 3)
    for p in res["pairs"]:
        assert len(p["trials"]) == 3
        assert all("trace" in t and "seed" in t for t in p["trials"])


class BrokenAgent:
    def run(self, prompt, sandbox):
        raise RuntimeError("api down")


def test_agent_errors_are_counted_not_hidden():
    res = run_suite(lambda s: BrokenAgent(), load_attacks(), TASKS, 2)
    summary = score(res, [t["name"] for t in BASE_TOOLS])
    assert summary["errors"] > 0
    assert all(p["successes"] == 0 for p in res["pairs"])   # looks "secure"...
    assert all(p["errors"] == 2 for p in res["pairs"])      # ...but the errors are recorded