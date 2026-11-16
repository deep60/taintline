"""Re-judge STORED traces with the CURRENT oracle, without calling the model again.
Canaries are regenerated from each trial's seed, so the judgement is exact."""
from __future__ import annotations

import copy

from .oracles import evaluate
from .sandbox import BASE_TOOLS, Sandbox, ToolCall
from .scoring import score, wilson
from .tasks import TASKS

_TASKS = {t.id: t for t in TASKS}


def _judge(trial: dict, task):
    sb = Sandbox(seed=trial["seed"])
    sb.calls = [ToolCall(c["tool"], c["args"], c["result"]) for c in trial["trace"]]
    v = evaluate(sb, task, trial["answer"])
    trial.update(oracle_success=v.success, severity=v.severity, leaked=v.leaked,
                 task_completed=v.task_completed, unrequested_outbound=v.unrequested_outbound)
    return v


def rescore(results: dict) -> tuple[dict, dict]:
    """Returns (result, summary) ready for report.write_report."""
    out = {k: copy.deepcopy(v) for k, v in results.items() if k != "summary"}
    for p in out["pairs"]:
        task = _TASKS[p["task"]]
        succ = completed = 0
        sevs, example = [], None
        for t in p["trials"]:
            v = _judge(t, task)
            completed += v.task_completed
            if v.success:
                succ += 1
                sevs.append(v.severity)
                example = example or {"leaked": v.leaked, "trace": t["trace"]}
        n = p["n"]
        lo, hi = wilson(succ, n)
        p.update(successes=succ, asr=succ / n, ci=[lo, hi], max_severity=max(sevs, default=0),
                 task_completion=completed / n, example=example)
    for b in out["baseline"]:
        task = _TASKS[b["task"]]
        done = fa = un = 0
        for t in b["trials"]:
            v = _judge(t, task)
            done += v.task_completed
            fa += v.success
            un += v.unrequested_outbound
        n = b["n"]
        b.update(completion=done / n, false_alarm=fa / n, unrequested_outbound=un / n)
    summary = score(out, [t["name"] for t in BASE_TOOLS])
    out["meta"] = {**out.get("meta", {}), "rescored": True}
    return out, summary