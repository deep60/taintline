"""taintline compare: exact test, multiple-comparison correction, and honest verdicts."""
import json

import pytest

from taintline.report.compare import compare, compare_markdown, fisher_exact, holm


def test_fisher_exact_matches_known_values():
    assert fisher_exact(1, 10, 11, 14) == pytest.approx(0.002759, abs=1e-5)   # classic 2x2 example
    assert fisher_exact(3, 10, 3, 10) == pytest.approx(1.0)
    assert fisher_exact(0, 5, 0, 5) == 1.0


def test_holm_adjusts_and_keeps_order():
    adj = holm([0.01, 0.04, 0.03])
    assert adj == pytest.approx([0.03, 0.06, 0.06])


def _suite(path, per_attack, utility=1.0, verdict="solid", lab="notes"):
    pairs = [{"attack": k, "task": "t", "n": n, "delivered": d} for k, (d, n) in per_attack.items()]
    d = sum(x["delivered"] for x in pairs)
    t = sum(x["n"] for x in pairs)
    path.write_text(json.dumps({"lab": lab, "pairs": pairs, "overall": {"delivered": d, "trials": t},
                                "summary": {"baseline_utility": utility, "baseline_false_alarm": 0},
                                "trust": {"verdict": verdict}}))
    return str(path)


def test_a_real_improvement_is_called(tmp_path):
    a = _suite(tmp_path / "a.json", {"x": (15, 20), "y": (14, 20)})
    b = _suite(tmp_path / "b.json", {"x": (1, 20), "y": (2, 20)})
    r = compare(a, b)
    assert r["overall"]["verdict"] == "B leaks less" and r["overall"]["p"] < 0.001
    assert all(row["verdict"] == "B leaks less" for row in r["attacks"])
    assert "**B leaks less than A**" in compare_markdown(r)


def test_small_samples_say_not_shown_not_no_difference(tmp_path):
    a = _suite(tmp_path / "a.json", {"x": (2, 3)})
    b = _suite(tmp_path / "b.json", {"x": (0, 3)})
    r = compare(a, b)
    assert r["overall"]["verdict"] == "not shown"
    assert "not evidence of no difference" in compare_markdown(r)


def test_one_lucky_attack_out_of_many_is_not_called(tmp_path):
    many = {f"a{i}": (5, 10) for i in range(20)}
    b_many = {**many, "a0": (0, 10)}            # raw p ~0.03, but one of twenty
    r = compare(_suite(tmp_path / "a.json", many), _suite(tmp_path / "b.json", b_many))
    row = next(x for x in r["attacks"] if x["name"] == "a0")
    assert row["p"] < 0.05 and row["verdict"] == "not shown"


def test_warnings_for_untrusted_runs_lost_utility_and_mismatches(tmp_path):
    a = _suite(tmp_path / "a.json", {"x": (5, 10), "only_a": (1, 10)})
    b = _suite(tmp_path / "b.json", {"x": (0, 10)}, utility=0.5, verdict="unreliable", lab="inbox")
    w = " ".join(compare(a, b)["warnings"])
    assert "different targets" in w and "only_a" in w and "run B's own trust verdict" in w
    assert "fewer clean tasks" in w


def test_live_run_results_compare_overall(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps({"server": "notes", "n": 20, "canary_arrived": 18}))
    (tmp_path / "b.json").write_text(json.dumps({"server": "notes", "n": 20, "canary_arrived": 2}))
    r = compare(str(tmp_path / "a.json"), str(tmp_path / "b.json"))
    assert r["overall"]["verdict"] == "B leaks less" and r["attacks"] == []


def test_cli_fail_if_worse(tmp_path, capsys):
    from taintline.cli import main
    a = _suite(tmp_path / "a.json", {"x": (1, 20)})
    b = _suite(tmp_path / "b.json", {"x": (15, 20)})
    with pytest.raises(SystemExit) as e:
        main(["compare", a, b, "--fail-if-worse", "--out", str(tmp_path / "cmp")])
    assert e.value.code == 1 and "B leaks MORE" in capsys.readouterr().out
    assert json.loads((tmp_path / "cmp" / "compare.json").read_text())["overall"]["verdict"] == "B leaks more"
    main(["compare", b, a, "--fail-if-worse"])       # an improvement passes
