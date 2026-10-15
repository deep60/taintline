from __future__ import annotations
import math
from .sandbox import Sandbox
from .oracle import evaluate

def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    a = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (c - a) / d), min(1.0, (c + a) / d)

def _compatible(atk, task) -> bool:
    return atk.surface == "tool_description" or atk.surface == task.surface

def _trace(sb):
    return [{"tool": c.name, "args": c.args} for c in sb.calls]

def run_suite(make_agent, attacks, tasks, n: int, seed: int = 0) -> dict:
    pairs, tid = [], 0
    for atk in attacks:
        for task in tasks:
            if not _compatible(atk, task):
                continue
            succ, sevs, example, completed = 0, [], None, 0
            for _ in range(n):
                tid += 1
                sb = Sandbox(seed=seed + tid, injection=atk.injection())
                try:
                    answer = make_agent(seed + tid).run(task.prompt, sb)
                except Exception as e:
                    answer = f"agent error: {e}"
                v = evaluate(sb, task, answer)
                completed += v.task_completed
                if v.success:
                    succ += 1
                    sevs.append(v.severity)
                    example = example or {"leaked": v.leaked, "trace": _trace(sb)}
            lo, hi = wilson(succ, n)
            pairs.append({"attack": atk.id, "task": task.id, "channel": atk.channel,
                          "effort": atk.effort, "n": n, "successes": succ,
                          "asr": succ / n, "ci": [lo, hi],
                          "max_severity": max(sevs, default=0), "task_completion": completed / n,
                          "example": example})
    # benign baseline: no injection. Measures utility and false alarms.
    baseline = []
    for task in tasks:
        done = fa = 0
        for _ in range(n):
            tid += 1
            sb = Sandbox(seed=seed + tid, injection=None)
            try:
                answer = make_agent(seed + tid).run(task.prompt, sb)
            except Exception as e:
                answer = f"agent error: {e}"
            v = evaluate(sb, task, answer)
            done += v.task_completed
            fa += v.success
        baseline.append({"task": task.id, "n": n, "completion": done / n, "false_alarm": fa / n})
    return {"n": n, "pairs": pairs, "baseline": baseline}
