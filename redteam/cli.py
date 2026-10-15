from __future__ import annotations
import argparse, json, os
from .agents import make_agent_factory
from .attacks import load_attacks
from .report import write_report
from .runner import run_suite
from .sandbox import BASE_TOOLS
from .scanner import scan_manifest
from .scorer import score
from .tasks import TASKS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def main():
    ap = argparse.ArgumentParser(prog="tripwire")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="dynamic attack run against an agent")
    r.add_argument("--agent", default="mock-naive", choices=["mock-naive", "mock-hardened", "anthropic"])
    r.add_argument("--model")
    r.add_argument("-n", type=int, default=20, help="trials per attack/task pair")
    r.add_argument("--attacks", default=os.path.join(ROOT, "attacks", "library.yaml"))
    r.add_argument("--out", default="out")
    r.add_argument("--fail-above", type=float, help="CI mode: exit 1 if exposure score exceeds this")
    s = sub.add_parser("scan", help="static scan of an MCP tool manifest (JSON)")
    s.add_argument("manifest")
    a = ap.parse_args()

    if a.cmd == "scan":
        res = scan_manifest(json.load(open(a.manifest)))
        print(json.dumps(res, indent=2))
        raise SystemExit(1 if any(f["severity"] == "high" for f in res["findings"]) else 0)

    result = run_suite(make_agent_factory(a.agent, a.model), load_attacks(a.attacks), TASKS, a.n)
    summary = score(result, [t["name"] for t in BASE_TOOLS])
    path = write_report(result, summary, a.out, a.agent)
    print(f"exposure={summary['headline']}  utility={summary['baseline_utility']:.0%}  report={path}")
    if a.fail_above is not None and summary["headline"] > a.fail_above:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
