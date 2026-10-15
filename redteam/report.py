from __future__ import annotations
import json, os

def write_report(result: dict, summary: dict, out_dir: str, label: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    json.dump({"summary": summary, **result}, open(f"{out_dir}/results.json", "w"), indent=2)
    L = [f"# Agent exposure report: {label}", "",
         f"**Exposure score: {summary['headline']}/100** (relative, uncalibrated weights; see scorer.py)", "",
         f"- Lethal trifecta present: **{summary['trifecta_complete']}** {summary['trifecta']}",
         f"- Benign baseline task completion: **{summary['baseline_utility']:.0%}**; "
         f"false-alarm rate: **{summary['baseline_false_alarm']:.0%}**",
         f"- Trials per attack/task pair: {result['n']}", ""]
    if summary["baseline_utility"] < 0.9:
        L += ["> **Warning:** baseline utility is low. A low attack success rate here may mean "
              "the agent is simply broken, not secure.", ""]
    L += ["| attack | task | effort | ASR | 95% CI | max sev | exposure |", "|---|---|---|---|---|---|---|"]
    for p in sorted(result["pairs"], key=lambda p: -p["exposure"]):
        L.append(f"| {p['attack']} | {p['task']} | {p['effort']} | {p['asr']:.0%} | "
                 f"{p['ci'][0]:.0%}-{p['ci'][1]:.0%} | {p['max_severity']} | {100*p['exposure']:.1f} |")
    ex = next((p for p in sorted(result["pairs"], key=lambda p: -p["exposure"]) if p["example"]), None)
    if ex:
        L += ["", f"## Example successful trace: {ex['attack']} on {ex['task']}",
              f"Leaked canaries: {ex['example']['leaked'] or 'none (attacker contacted)'}", "```"]
        L += [f"{i+1}. {t['tool']}({json.dumps(t['args'])[:140]})" for i, t in enumerate(ex["example"]["trace"])]
        L += ["```"]
    path = f"{out_dir}/report.md"
    open(path, "w").write("\n".join(L) + "\n")
    return path
