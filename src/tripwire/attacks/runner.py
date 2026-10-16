"""Run every compatible (attack, task) pair N times, then a benign baseline."""
from __future__ import annotations

from ..gateway.transcript import Transcript
from ..oracles import evaluate
from ..sandbox import Sandbox
from ..scoring.asr import wilson


def _compatible(atk, task) -> bool:
    return atk.surface == "tool_description" or atk.surface == task.surface


def _run_one(agent, prompt: str, sb: Sandbox) -> tuple[str, bool]:
    """Returns (answer, errored). Errors must be counted: a broken agent or API
    connection would otherwise look like a secure agent."""
    try:
        return agent.run(prompt, sb), False
    except Exception as e:
        return f"agent error: {e}", True


def run_suite(make_agent, attacks, tasks, n: int, seed: int = 0) -> dict:
    pairs, tid = [], 0
    for atk in attacks:
        for task in tasks:
            if not _compatible(atk, task):
                continue
            succ = completed = errors = 0
            sevs, trials, example = [], [], None
            for _ in range(n):
                tid += 1
                sb = Sandbox(seed=seed + tid, injection=atk.injection())
                answer, err = _run_one(make_agent(seed + tid), task.prompt, sb)
                v = evaluate(sb, task, answer)
                trace = Transcript.from_sandbox(task, answer, sb).to_dict()["trace"]
                errors += err
                completed += v.task_completed
                trials.append({
                    "seed": seed + tid, "error": err, "oracle_success": v.success,
                    "severity": v.severity, "leaked": v.leaked,
                    "task_completed": v.task_completed, "answer": answer, "trace": trace,
                })
                if v.success:
                    succ += 1
                    sevs.append(v.severity)
                    example = example or {"leaked": v.leaked, "trace": trace}
            lo, hi = wilson(succ, n)
            pairs.append({
                "attack": atk.id, "task": task.id, "channel": atk.channel,
                "effort": atk.effort, "n": n, "successes": succ, "asr": succ / n,
                "ci": [lo, hi], "max_severity": max(sevs, default=0),
                "task_completion": completed / n, "errors": errors,
                "example": example, "trials": trials,
            })
    baseline = []
    for task in tasks:
        done = fa = errors = 0
        for _ in range(n):
            tid += 1
            sb = Sandbox(seed=seed + tid, injection=None)
            answer, err = _run_one(make_agent(seed + tid), task.prompt, sb)
            v = evaluate(sb, task, answer)
            errors += err
            done += v.task_completed
            fa += v.success
        baseline.append({"task": task.id, "n": n, "completion": done / n,
                         "false_alarm": fa / n, "errors": errors})
    return {"n": n, "pairs": pairs, "baseline": baseline}
