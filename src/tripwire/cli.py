from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from . import meta
from .attacks import load_attacks, mutate
from .attacks.runner import run_suite
from .labeling import format_gate, gate0, make_sheet
from .report import write_report
from .sandbox import BASE_TOOLS
from .scanner import scan_manifest
from .scanner.auth_checks import check_client_config
from .scanner.enumerate import load_tools
from .scanner.rugpull import diff_pins, pin
from .scoring import score
from .targets import AGENT_KINDS, make_agent_factory
from .tasks import TASKS


def _config() -> dict:
    p = Path("tripwire.yaml")
    return (yaml.safe_load(p.read_text()) or {}) if p.exists() else {}


def main(argv=None):
    cfg = _config()
    ap = argparse.ArgumentParser(prog="tripwire")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="dynamic attack run against an agent")
    r.add_argument("--agent", default=cfg.get("agent", "mock-naive"), choices=AGENT_KINDS)
    r.add_argument("--model", default=cfg.get("model"))
    r.add_argument("--system", help="override the agent's system prompt (positive controls)")
    r.add_argument("-n", type=int, default=cfg.get("n", 20), help="trials per attack/task pair")
    r.add_argument("--attacks", help="YAML file or directory (default: bundled chains)")
    r.add_argument("--mutators", default="", help="comma list, e.g. base64,homoglyph")
    r.add_argument("--out", default=cfg.get("out", "out"))
    r.add_argument("--fail-above", type=float, help="CI mode: exit 1 if score exceeds this")

    s = sub.add_parser("scan", help="static scan of an MCP tool manifest (JSON)")
    s.add_argument("manifest")

    pn = sub.add_parser("pin", help="save tool hashes (for rug-pull detection)")
    pn.add_argument("manifest")
    pn.add_argument("--out", default="pins.json")

    d = sub.add_parser("diff", help="compare a manifest against saved pins")
    d.add_argument("pins")
    d.add_argument("manifest")

    c = sub.add_parser("config-check", help="check an MCP client config for plaintext secrets/HTTP")
    c.add_argument("config")

    ls = sub.add_parser("label-sheet", help="G0: build a blind sheet of traces to hand-label")
    ls.add_argument("results", nargs="+", help="one or more results.json files")
    ls.add_argument("--n", type=int, default=20)
    ls.add_argument("--seed", type=int, default=0)
    ls.add_argument("--out", default="out/labels")

    g = sub.add_parser("gate0", help="G0: check your labels and both runs against the gate")
    g.add_argument("--default", required=True, help="results.json of the default real-model run")
    g.add_argument("--control", required=True, help="results.json of the gullible-control run")
    g.add_argument("--labels", required=True, help="your filled-in labels CSV")
    g.add_argument("--key", required=True, help="labels_key.json from label-sheet")

    a = ap.parse_args(argv)

    if a.cmd == "scan":
        res = scan_manifest(json.loads(Path(a.manifest).read_text()))
        print(json.dumps(res, indent=2))
        raise SystemExit(1 if any(f["severity"] == "high" for f in res["findings"]) else 0)

    if a.cmd == "pin":
        pins = pin(load_tools(a.manifest))
        Path(a.out).write_text(json.dumps(pins, indent=2))
        print(f"pinned {len(pins)} tools -> {a.out}")
        return

    if a.cmd == "diff":
        changes = diff_pins(json.loads(Path(a.pins).read_text()), load_tools(a.manifest))
        print(json.dumps(changes, indent=2))
        raise SystemExit(1 if changes else 0)

    if a.cmd == "config-check":
        found = check_client_config(json.loads(Path(a.config).read_text()))
        print(json.dumps(found, indent=2))
        raise SystemExit(1 if found else 0)

    if a.cmd == "label-sheet":
        res = make_sheet(a.results, n=a.n, seed=a.seed, out_dir=a.out)
        print(f"sheet: {res['csv']}  ({res['rows']} rows, {res['oracle_positive_in_sheet']} oracle-positive)")
        print(f"key (do NOT open before labeling): {res['key']}")
        for w in res["warnings"]:
            print(f"WARNING: {w}")
        return

    if a.cmd == "gate0":
        res = gate0(a.default, a.control, a.labels, a.key)
        print(format_gate(res))
        raise SystemExit(0 if res["passed"] else 1)

    mutator_names = [m for m in a.mutators.split(",") if m]
    attacks = load_attacks(a.attacks)
    for m in mutator_names:
        attacks += [mutate(x, m) for x in load_attacks(a.attacks)]
    result = run_suite(make_agent_factory(a.agent, a.model, a.system), attacks, TASKS, a.n)
    result["meta"] = meta.collect(agent=a.agent, model=a.model, system_override=bool(a.system),
                                  n=a.n, attacks=attacks, mutators=mutator_names)
    summary = score(result, [t["name"] for t in BASE_TOOLS])
    path = write_report(result, summary, a.out, a.agent)
    print(f"exposure={summary['headline']}  utility={summary['baseline_utility']:.0%}  "
          f"errors={summary['errors']}  report={path}")
    if a.fail_above is not None and summary["headline"] > a.fail_above:
        raise SystemExit(1)