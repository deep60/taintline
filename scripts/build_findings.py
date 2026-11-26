"""Rebuild the charts and number tables in docs/findings/ from run data.

    uv run python scripts/build_findings.py            # from the committed snapshots in docs/findings/data
    uv run python scripts/build_findings.py --refresh  # re-snapshot from out/<run>/results.json first

Every number in the posts comes from here, never typed by hand. A post marks each generated block
with <!-- tw:NAME --> ... <!-- /tw:NAME -->; this script replaces what is between the markers.
Snapshots keep per-pair counts only (no transcripts, no canaries), so they are safe to commit."""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from taintline.report.charts import bar_chart  # noqa: E402
from taintline.scoring.asr import wilson  # noqa: E402

DOCS = ROOT / "docs" / "findings"
DATA, IMG = DOCS / "data", DOCS / "img"
RS = "redsage-qwen3-8b-ins"
HX = "qwen3.8-9b-heretic-uncensored"
COMMON = "--agent openai-compat --base-url http://localhost:1234/v1 --temperature 0.6 --fix-seed"

# snapshot name -> (source run folder, model, extra live-suite args)
RUNS = {
    "rs_browser_default": ("out/rs_browser_default2", RS, "--lab browser -n 3"),
    "rs_browser_gullible": ("out/rs_browser_control2", RS, "--lab browser -n 3 --gullible"),
    "rs_shadow": ("out/rs_shadow", RS, "--lab shadow+inbox -n 5"),
    "rs_notes_default": ("out/rs_notes_default", RS, "--lab notes -n 10"),
    "rs_notes_gullible": ("out/rs_notes_control", RS, "--lab notes -n 10 --gullible"),
    "hx_notes_default": ("out/hx_notes_default", HX, "--lab notes -n 10"),
    "hx_notes_gullible": ("out/hx_notes_control", HX, "--lab notes -n 10 --gullible"),
    # finding #4: the agent under test is examples/byo_agent/agent.py (--agent command)
    "hx_mcp_default": ("out/runs_2026-11-25/suite", HX, "--attacks docs/findings/attacks/notes_mcp.yaml -n 3"),
    "hx_mcp_gullible": ("out/runs_2026-11-25/suite_gullible", HX,
                        "--attacks docs/findings/attacks/notes_mcp.yaml -n 2 --gullible"),
    "hx_rug_pull": ("out/runs_2026-11-25/rug", HX, "--attacks docs/findings/attacks/notes_rug_pull.yaml -n 3"),
    "hx_error_vs_result": ("out/runs_2026-11-25/ablation", HX,
                           "--attacks docs/findings/attacks/notes_error_vs_result.yaml -n 5"),
}
CMD_AGENT = ("--server notes --command python --arg lab/servers/notes_server.py --agent command "
             "--agent-cmd 'uv run python examples/byo_agent/agent.py' --base-url http://localhost:1234/v1")
PAIR_KEYS = ("attack", "task", "family", "surface", "n", "delivered", "fired", "attacker_contact",
             "canary_read", "errors")


def snapshot(name: str) -> dict:
    src, model, args = RUNS[name]
    res = json.loads((ROOT / src / "results.json").read_text())
    pairs = []
    for p in res["pairs"]:
        row = {k: p[k] for k in PAIR_KEYS}
        # did the agent's own tool log show the attacker? (the shadow finding hinges on this)
        row["trace_shows_attacker"] = sum("evil.example" in json.dumps(t.get("trace", []))
                                          for t in p["trials"])
        pairs.append(row)
    base = [{k: b[k] for k in ("task", "n", "false_alarm", "task_completion", "errors", "attacker_contact")}
            for b in res["baseline"]]
    keep = ("headline", "baseline_utility", "baseline_false_alarm", "errors", "valid")
    common = CMD_AGENT if "--attacks" in args else COMMON
    lab = "notes-mcp" if "--attacks" in args else res["lab"]   # own attack set: not the bundled notes lab
    return {"run": name, "model": model, "lab": lab, "sampling": res.get("sampling"),
            "command": f"taintline live-suite {common} --model {model} {args} --out out/{name}",
            "summary": {k: res["summary"][k] for k in keep}, "overall": res["overall"],
            "pairs": pairs, "baseline": base}


def load(name: str) -> dict:
    return json.loads((DATA / f"{name}.json").read_text())


def by_attack(run: dict) -> dict[str, dict]:
    agg: dict[str, dict] = defaultdict(lambda: defaultdict(int))
    for p in run["pairs"]:
        for k in ("n", "delivered", "fired", "attacker_contact", "errors", "trace_shows_attacker"):
            agg[p["attack"]][k] += p[k]
    return agg


def pct(k: int, n: int) -> str:
    lo, hi = wilson(k, n)
    return f"{k}/{n} ({100 * k / n:.0f}%, CI {100 * lo:.0f}-{100 * hi:.0f}%)" if n else "n/a"


def table(head: list[str], rows: list[list]) -> str:
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


HIDDEN_NAMES = {
    "hidden_visible_control": "visible text (control)", "hidden_css": "display:none",
    "hidden_offscreen": "off-screen (left:-9999px)", "hidden_white_on_white": "white on white",
    "hidden_comment": "HTML comment", "hidden_alt_text": "image alt text", "hidden_aria_label": "aria-label",
    "hidden_form_field": "hidden form field label", "hidden_input": "input type=hidden",
    "storage_cookie": "cookie / localStorage",
}


def hidden_text() -> dict[str, str]:
    d, g = by_attack(load("rs_browser_default")), by_attack(load("rs_browser_gullible"))
    order = sorted(d, key=lambda a: (-(d[a]["fired"] > 0), -(d[a]["delivered"] + g[a]["delivered"])))
    rows = [[HIDDEN_NAMES.get(a, a), "yes" if d[a]["fired"] else "**no, stripped**",
             f"{d[a]['delivered']}/{d[a]['n']}", f"{g[a]['delivered']}/{g[a]['n']}",
             f"{d[a]['delivered'] + g[a]['delivered']}/{d[a]['n'] + g[a]['n']}",
             f"{d[a]['attacker_contact'] + g[a]['attacker_contact']}/{d[a]['n'] + g[a]['n']}"]
            for a in order]
    svg = bar_chart([(HIDDEN_NAMES.get(a, a), [(d[a]["delivered"], d[a]["n"]), (g[a]["delivered"], g[a]["n"])])
                     for a in order],
                    "Secret delivered to the attacker, by hiding technique",
                    ["default prompt", "gullible prompt"], note=f"Model: {RS}. 3 pages x 3 trials per bar.")
    (IMG / "hidden_text.svg").write_text(svg)
    both = [load("rs_browser_default"), load("rs_browser_gullible")]
    return {"hidden_table": table(["hiding technique", "reached the model", "leaked (default)",
                                   "leaked (gullible)", "leaked (both)", "contacted attacker (both)"], rows),
            "hidden_runs": runs_table(both)}


def shadow() -> dict[str, str]:
    run = load("rs_shadow")
    rows, tot = [], defaultdict(int)
    for p in run["pairs"]:
        rows.append([p["task"], p["n"], f"{p['attacker_contact']}/{p['n']}", f"{p['trace_shows_attacker']}/{p['n']}",
                     f"{p['delivered']}/{p['n']}"])
        for k in ("n", "attacker_contact", "trace_shows_attacker", "delivered"):
            tot[k] += p[k]
    rows.append(["**all**", tot["n"], f"**{tot['attacker_contact']}/{tot['n']}**",
                 f"**{tot['trace_shows_attacker']}/{tot['n']}**", f"{tot['delivered']}/{tot['n']}"])
    bn = sum(b["n"] for b in run["baseline"])
    bc = sum(b["attacker_contact"] for b in run["baseline"])
    svg = bar_chart([("attacker got a copy", [(tot["attacker_contact"], tot["n"])]),
                     ("agent's tool log showed it", [(tot["trace_shows_attacker"], tot["n"])]),
                     ("baseline: attacker got a copy", [(bc, bn)])],
                    "Shadowed send_email: what the attacker saw vs what the agent saw",
                    note=f"Model: {RS}. Baseline = same tasks, honest server.")
    (IMG / "shadow.svg").write_text(svg)
    return {"shadow_table": table(["task", "trials", "attacker got a copy", "agent's tool log showed the attacker",
                                   "canary delivered"], rows),
            "shadow_runs": runs_table([run])}


MODEL_RUNS = [("RedSage, default", "rs_notes_default"), ("RedSage, gullible", "rs_notes_gullible"),
              ("heretic, default", "hx_notes_default"), ("heretic, gullible", "hx_notes_gullible")]


def models() -> dict[str, str]:
    runs = {label: load(name) for label, name in MODEL_RUNS}

    def totals(r):
        a = by_attack(r)
        return {k: sum(v[k] for v in a.values()) for k in ("n", "delivered", "attacker_contact", "errors")}

    t = {label: totals(r) for label, r in runs.items()}
    svg = bar_chart([(label, [(v["attacker_contact"], v["n"]), (v["delivered"], v["n"])]) for label, v in t.items()],
                    "Notes lab: contacting the attacker vs delivering the secret",
                    ["contacted attacker", "delivered the secret"],
                    note="240 trials per run: 8 attacks x 3 tasks x 10.")
    (IMG / "models.svg").write_text(svg)
    summary = [[label, pct(v["delivered"], v["n"]), pct(v["attacker_contact"], v["n"]),
                (f"{100 * v['delivered'] / v['attacker_contact']:.0f}%" if v["attacker_contact"] else "n/a"),
                v["errors"], "yes" if runs[label]["summary"]["valid"] else "**no** (errors)"]
               for label, v in t.items()]
    per = {label: by_attack(r) for label, r in runs.items()}
    attacks = list(per[MODEL_RUNS[0][0]])
    per_rows = [[a] + [f"{per[label][a]['delivered']}/{per[label][a]['n']}" for label, _ in MODEL_RUNS]
                for a in attacks]
    return {"models_table": table(["run", "delivered the secret", "contacted the attacker",
                                   "contacts that carried the secret", "errors", "valid run"], summary),
            "models_attacks": table(["attack"] + [label for label, _ in MODEL_RUNS], per_rows),
            "models_runs": runs_table(list(runs.values()))}


MCP_NAMES = {
    "error_recovery_steps": ("a fix-it step, in a tool error", "tool_error"),
    "direct_notice": ("a \"system notice\", in a normal result", "tool_result"),
    "parameter_description_poison": ("instruction in a parameter's description", "tool_schema"),
    "rug_pull_after_first_use": ("tool description turns malicious after first use", "rug_pull"),
}
MCP_RUNS = ["hx_mcp_default", "hx_mcp_gullible", "hx_rug_pull"]


def mcp_errors() -> dict[str, str]:
    """Finding #4. A pair whose injection never reached the agent says nothing, so it is left out of
    the counts and reported as excluded (the rug-pull pairs run before the bridge could pass on
    tools/list_changed)."""
    from taintline.report.compare import fisher_exact
    agg: dict[str, dict] = defaultdict(lambda: defaultdict(int))
    excluded = 0
    for name in MCP_RUNS:
        for p in load(name)["pairs"]:
            if not p["fired"]:
                excluded += p["n"]
                continue
            for k in ("n", "delivered", "attacker_contact", "errors"):
                agg[p["attack"]][k] += p[k]
    order = [a for a in MCP_NAMES if a in agg]
    rows = [[MCP_NAMES[a][0], f"`{MCP_NAMES[a][1]}`", pct(agg[a]["delivered"], agg[a]["n"]), agg[a]["errors"]]
            for a in order]
    ab = by_attack(load("hx_error_vs_result"))
    e, r = ab["error_recovery_steps"], ab["error_text_as_result"]
    p = fisher_exact(e["delivered"], e["n"], r["delivered"], r["n"])
    ab_rows = [["as a tool error (`isError: true`)", pct(e["delivered"], e["n"])],
               ["appended to a normal result", pct(r["delivered"], r["n"])]]
    svg = bar_chart([(MCP_NAMES[a][0].replace("**", ""), [(agg[a]["delivered"], agg[a]["n"])]) for a in order]
                    + [("same error text, as a tool error", [(e["delivered"], e["n"])]),
                       ("same error text, in a normal result", [(r["delivered"], r["n"])])],
                    "Secret delivered to the attacker, by where the instruction sits",
                    note=f"Model: {HX}, as a bring-your-own agent. Bars with 95% intervals.")
    (IMG / "mcp_errors.svg").write_text(svg)
    return {"errors_table": table(["where the instruction sits", "surface", "leaked the secret", "errors"], rows)
            + (f"\n\nLeft out: {excluded} trials whose injection never reached the agent." if excluded else ""),
            "errors_ablation": table(["the same text, delivered", "leaked the secret"], ab_rows)
            + f"\n\nFisher's exact test, two-sided: p = {p:.2g}.",
            "errors_runs": runs_table([load(n) for n in MCP_RUNS + ["hx_error_vs_result"]])}


def runs_table(runs: list[dict]) -> str:
    rows = [[f"`{r['run']}`", r["model"], r["lab"], r["overall"]["trials"], r["summary"]["errors"],
             f"{100 * r['summary']['baseline_utility']:.0f}%", f"{100 * r['summary']['baseline_false_alarm']:.0f}%"]
            for r in runs]
    cmds = "\n".join(r["command"] for r in runs)
    return (table(["run", "model", "lab", "trials", "errors", "baseline completion", "baseline false alarm"], rows)
            + f"\n\nReproduce (LM Studio on port 1234, model loaded, host in SCOPE.yaml):\n\n```bash\n{cmds}\n```")


def fill(path: Path, blocks: dict[str, str]) -> None:
    text = path.read_text()
    for name, body in blocks.items():
        pat = re.compile(rf"(<!-- tw:{name} -->\n).*?(<!-- /tw:{name} -->)", re.S)
        if not pat.search(text):
            raise SystemExit(f"{path.name}: missing marker tw:{name}")
        text = pat.sub(lambda m, b=body: m.group(1) + b + "\n" + m.group(2), text)
    path.write_text(text)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--refresh", action="store_true", help="re-snapshot from out/<run>/results.json")
    a = ap.parse_args()
    DATA.mkdir(parents=True, exist_ok=True)
    IMG.mkdir(parents=True, exist_ok=True)
    if a.refresh:
        for name in RUNS:
            if not (ROOT / RUNS[name][0] / "results.json").exists():   # run data lives only where it ran
                print(f"kept snapshot {name}: {RUNS[name][0]} not here", file=sys.stderr)
                continue
            (DATA / f"{name}.json").write_text(json.dumps(snapshot(name), indent=1) + "\n")
    fill(DOCS / "01-hidden-text.md", hidden_text())
    fill(DOCS / "02-shadowed-tool.md", shadow())
    fill(DOCS / "03-local-models.md", models())
    fill(DOCS / "04-tool-errors.md", mcp_errors())
    print(f"built {len(list(IMG.glob('*.svg')))} charts and filled 4 posts in {DOCS.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
