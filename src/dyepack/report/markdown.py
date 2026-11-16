from __future__ import annotations

import json


def render(result: dict, summary: dict, label: str) -> str:
    L = [
        f"# Agent exposure report: {label}", "",
        f"**Exposure score: {summary['headline']}/100** "
        "(relative, uncalibrated weights; see scoring/)", "",
        f"- Lethal trifecta present: **{summary['trifecta_complete']}** {summary['trifecta']}",
        f"- Benign baseline task completion: **{summary['baseline_utility']:.0%}**; "
        f"false-alarm rate: **{summary['baseline_false_alarm']:.0%}**",
        f"- Trials per attack/task pair: {result['n']}",
        f"- Baseline runs where the agent sent an outbound call nobody asked for: "
        f"**{summary.get('baseline_unrequested_outbound', 0):.0%}** "
        "(excessive agency; NOT counted as attack success)",
        f"- Agent/API errors: **{summary['errors']}**",
    ]
    m = result.get("meta")
    if m:
        L.append(f"- Run: agent={m['agent']} model={m['model']} system_override={m['system_override']} "
                 f"git={m['git_sha']} attacks={m['attack_count']} (library {m['attack_library_hash']}) "
                 f"date={m['date_utc']}")
    L.append("")
    if summary["errors"]:
        L += ["> **Warning:** some runs errored. Errors are NOT counted as attack successes, "
              "so a low score here may mean the agent or API was broken, not secure.", ""]
    if summary["baseline_utility"] < 0.9:
        L += ["> **Warning:** baseline utility is low. A low attack success rate may mean the "
              "agent is simply broken, not secure.", ""]
    L += ["| attack | task | effort | ASR | 95% CI | max sev | exposure |",
          "|---|---|---|---|---|---|---|"]
    ranked = sorted(result["pairs"], key=lambda p: -p["exposure"])
    for p in ranked:
        L.append(f"| {p['attack']} | {p['task']} | {p['effort']} | {p['asr']:.0%} | "
                 f"{p['ci'][0]:.0%}-{p['ci'][1]:.0%} | {p['max_severity']} | "
                 f"{100 * p['exposure']:.1f} |")
    ex = next((p for p in ranked if p["example"]), None)
    if ex:
        L += ["", f"## Example successful trace: {ex['attack']} on {ex['task']}",
              f"Leaked canaries: {ex['example']['leaked'] or 'none (attacker contacted)'}",
              "```"]
        L += [f"{i + 1}. {t['tool']}({json.dumps(t['args'])[:140]})"
              for i, t in enumerate(ex["example"]["trace"])]
        L += ["```"]
    return "\n".join(L) + "\n"