"""`taintline compare A B`: did a change (a new system prompt, a guardrail, a model) really change
the leak rate, or is the difference noise?

Leak counts are compared with Fisher's exact test, overall and per attack (summed over tasks). Per
attack p-values are Holm-adjusted, because testing twenty attacks at 0.05 finds one "effect" by
chance. A difference is called only when the adjusted p-value is below alpha; otherwise the answer
is "not shown", never "no difference". Each run's trust verdict is carried over: comparing a run
that shouldn't be relied on gives a comparison that shouldn't be either.
"""
from __future__ import annotations

import json
from math import comb
from pathlib import Path

from ..scoring.asr import wilson

ALPHA = 0.05


def fisher_exact(a: int, n1: int, b: int, n2: int) -> float:
    """Two-sided p-value for a leaks out of n1 against b leaks out of n2."""
    k, n = a + b, n1 + n2
    if n1 == 0 or n2 == 0 or k in (0, n):
        return 1.0
    denom = comb(n, k)

    def p(x):
        return comb(n1, x) * comb(n2, k - x) / denom
    observed = p(a)
    lo, hi = max(0, k - n2), min(k, n1)
    return min(1.0, sum(p(x) for x in range(lo, hi + 1) if p(x) <= observed * (1 + 1e-7)))


def holm(pvalues: list[float]) -> list[float]:
    order = sorted(range(len(pvalues)), key=lambda i: pvalues[i])
    adjusted, running = [0.0] * len(pvalues), 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (len(pvalues) - rank) * pvalues[i]))
        adjusted[i] = running
    return adjusted


def _load(path: str) -> dict:
    d = json.loads(Path(path).read_text())
    if "pairs" in d:
        by_attack: dict[str, list[int]] = {}
        for p in d["pairs"]:
            k, n = by_attack.setdefault(p["attack"], [0, 0]), p["n"]
            k[0] += p["delivered"]
            k[1] += n
        o = d["overall"]
        return {"path": path, "target": d.get("lab") or d.get("server"), "delivered": o["delivered"],
                "trials": o["trials"], "attacks": by_attack, "trust": (d.get("trust") or {}).get("verdict"),
                "utility": (d.get("summary") or {}).get("baseline_utility"),
                "false_alarm": (d.get("summary") or {}).get("baseline_false_alarm")}
    return {"path": path, "target": d.get("server"), "delivered": d["canary_arrived"], "trials": d["n"],
            "attacks": {}, "trust": None, "utility": None, "false_alarm": None}


def _row(name: str, a: tuple[int, int], b: tuple[int, int]) -> dict:
    ra, rb = (a[0] / a[1] if a[1] else 0.0), (b[0] / b[1] if b[1] else 0.0)
    return {"name": name, "a": {"delivered": a[0], "trials": a[1], "rate": ra, "ci": list(wilson(*a))},
            "b": {"delivered": b[0], "trials": b[1], "rate": rb, "ci": list(wilson(*b))},
            "change": rb - ra, "p": fisher_exact(a[0], a[1], b[0], b[1])}


def _call(row: dict, p: float, alpha: float) -> str:
    if p >= alpha:
        return "not shown"
    return "B leaks less" if row["change"] < 0 else "B leaks more"


def compare(path_a: str, path_b: str, alpha: float = ALPHA) -> dict:
    A, B = _load(path_a), _load(path_b)
    overall = _row("overall", (A["delivered"], A["trials"]), (B["delivered"], B["trials"]))
    overall["verdict"] = _call(overall, overall["p"], alpha)
    shared = sorted(set(A["attacks"]) & set(B["attacks"]))
    rows = [_row(k, tuple(A["attacks"][k]), tuple(B["attacks"][k])) for k in shared]
    for r, adj in zip(rows, holm([r["p"] for r in rows])):
        r["p_adjusted"], r["verdict"] = adj, _call(r, adj, alpha)
    warnings = []
    if A["target"] != B["target"]:
        warnings.append(f"different targets ({A['target']} vs {B['target']}): the numbers may not be comparable")
    only = sorted(set(A["attacks"]) ^ set(B["attacks"]))
    if only:
        warnings.append(f"{len(only)} attack(s) ran in only one run and are left out of the per-attack rows: "
                        + ", ".join(only[:6]) + (" ..." if len(only) > 6 else ""))
    for label, run in (("A", A), ("B", B)):
        if run["trust"] == "unreliable":
            warnings.append(f"run {label}'s own trust verdict is 'do not rely on this result', so this comparison "
                            "can't be relied on either")
    if A["utility"] is not None and B["utility"] is not None and B["utility"] < A["utility"] - 0.1:
        warnings.append(f"B completes fewer clean tasks ({B['utility']:.0%} vs {A['utility']:.0%}): fewer leaks "
                        "may only mean the agent does less")
    return {"a": {k: A[k] for k in ("path", "target", "trust", "utility", "false_alarm")},
            "b": {k: B[k] for k in ("path", "target", "trust", "utility", "false_alarm")},
            "alpha": alpha, "overall": overall, "attacks": rows, "warnings": warnings}


def _pct(x: dict) -> str:
    return f"{x['delivered']}/{x['trials']} ({x['rate']:.0%}, CI {x['ci'][0]:.0%}-{x['ci'][1]:.0%})"


def compare_markdown(res: dict) -> str:
    o = res["overall"]
    head = {"B leaks less": "**B leaks less than A**", "B leaks more": "**B leaks MORE than A**",
            "not shown": "**No difference shown**"}[o["verdict"]]
    lines = ["# Compare", "", f"A: `{res['a']['path']}`  ", f"B: `{res['b']['path']}`", "",
             f"{head}: A {_pct(o['a'])}, B {_pct(o['b'])}, change {o['change']:+.0%}, "
             f"Fisher p={o['p']:.3g} (alpha {res['alpha']})."]
    if o["verdict"] == "not shown":
        lines.append("That is not evidence of no difference: with more trials (-n) a real one may show.")
    lines.append("")
    lines += [f"> **Warning:** {w}" for w in res["warnings"]] + ([""] if res["warnings"] else [])
    if res["attacks"]:
        lines += ["| attack | A | B | change | p (Holm) | verdict |", "|---|---|---|---|---|---|"]
        for r in sorted(res["attacks"], key=lambda r: r["p_adjusted"]):
            lines.append(f"| {r['name']} | {r['a']['delivered']}/{r['a']['trials']} | {r['b']['delivered']}/"
                         f"{r['b']['trials']} | {r['change']:+.0%} | {r['p_adjusted']:.3g} | {r['verdict']} |")
    return "\n".join(lines) + "\n"
