from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from . import meta
from .attacks import load_attacks, mutate
from .attacks.runner import run_suite
from .labeling import format_gate, gate0, make_sheet
from .report import write_report
from .rescore import rescore
from .sandbox import BASE_TOOLS
from .scanner import scan_manifest
from .scanner.auth_checks import check_client_config
from .scanner.enumerate import enumerate_server, inventory, load_tools
from .scanner.rugpull import check, diff_pins, pin
from .scope import Gate, OutOfScope, ScopeError, load_scope
from .scope.target import check_run
from .scoring import score
from .targets import AGENT_KINDS, make_agent_factory
from .tasks import TASKS

LIVE_ATTACKS = Path(__file__).parent / "attacks" / "live"


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
    r.add_argument("--base-url", default=cfg.get("base_url"), help="openai-compat: API base URL")
    r.add_argument("--api-key-env", default=cfg.get("api_key_env", "OPENAI_API_KEY"),
                   help="openai-compat: name of the env var holding the API key")
    r.add_argument("-n", type=int, default=cfg.get("n", 20), help="trials per attack/task pair")
    r.add_argument("--attacks", help="YAML file or directory (default: bundled chains)")
    r.add_argument("--mutators", default="", help="comma list, e.g. base64,homoglyph")
    r.add_argument("--out", default=cfg.get("out", "out"))
    r.add_argument("--fail-above", type=float, help="CI mode: exit 1 if score exceeds this")
    r.add_argument("--scope", default="SCOPE.yaml",
                   help="authorization file; required for any agent that contacts a network host")
    r.add_argument("--dry-run", action="store_true",
                   help="check scope and print the plan; make no model calls and touch no network")

    s = sub.add_parser("scan", help="static scan of an MCP tool manifest (JSON)")
    s.add_argument("manifest")

    pn = sub.add_parser("pin", help="save tool hashes (for rug-pull detection)")
    pn.add_argument("manifest")
    pn.add_argument("--out", default="pins.json")

    d = sub.add_parser("diff", help="compare a manifest against saved pins")
    d.add_argument("pins")
    d.add_argument("manifest")

    en = sub.add_parser("enumerate", help="list tools of a live stdio MCP server (scope-gated) and scan them")
    en.add_argument("--server", required=True, help="server name as listed in SCOPE.yaml")
    en.add_argument("--command", required=True, help="command that starts the server, e.g. python")
    en.add_argument("--arg", action="append", default=[], help="argument for --command (repeatable)")
    en.add_argument("--scope", default="SCOPE.yaml")
    en.add_argument("--timeout", type=float, default=30.0)
    en.add_argument("--json", action="store_true", help="print only the tool list (feed it to `pin`/`diff`)")

    mo = sub.add_parser("monitor", help="re-enumerate a live server and alert if any tool changed since pinned")
    mo.add_argument("--server", required=True, help="server name as listed in SCOPE.yaml")
    mo.add_argument("--command", required=True)
    mo.add_argument("--arg", action="append", default=[])
    mo.add_argument("--scope", default="SCOPE.yaml")
    mo.add_argument("--timeout", type=float, default=30.0)
    mo.add_argument("--pins", default="pins.json", help="pin file; created as the baseline if missing")
    mo.add_argument("--update", action="store_true", help="accept the current tools as the new baseline")

    lv = sub.add_parser("live-run", help="agent vs a REAL stdio MCP server via the proxy; sink proves the leak")
    lv.add_argument("--server", required=True)
    lv.add_argument("--command", required=True)
    lv.add_argument("--arg", action="append", default=[])
    lv.add_argument("--collaborator", default="http://127.0.0.1:8099", help="running sink (lab/collaborator/server.py)")
    lv.add_argument("--inject", choices=["none", "result", "description"], default="result")
    lv.add_argument("--payload", help="injection text (default: ask the agent to email the secret note)")
    lv.add_argument("--agent", default=cfg.get("agent", "mock-naive"), choices=AGENT_KINDS)
    lv.add_argument("--model", default=cfg.get("model"))
    lv.add_argument("--system")
    lv.add_argument("--gullible", action="store_true",
                    help="positive control: tell the model to obey instructions found in tool output")
    lv.add_argument("--base-url", default=cfg.get("base_url"))
    lv.add_argument("--api-key-env", default=cfg.get("api_key_env", "OPENAI_API_KEY"))
    lv.add_argument("-n", type=int, default=5)
    lv.add_argument("--scope", default="SCOPE.yaml")
    lv.add_argument("--out", default="out/live")

    ls2 = sub.add_parser("live-suite", help="all live attacks x all live tasks vs a real stdio MCP server")
    for flag, kw in [("--server", dict(required=True)), ("--command", dict(required=True)),
                     ("--collaborator", dict(default="http://127.0.0.1:8099")),
                     ("--attacks", dict(help="YAML file/dir (default: bundled lab/notes attacks)")),
                     ("--mutators", dict(default="", help="comma list, e.g. base64,homoglyph")),
                     ("--agent", dict(default=cfg.get("agent", "mock-naive"), choices=AGENT_KINDS)),
                     ("--model", dict(default=cfg.get("model"))), ("--system", dict()),
                     ("--base-url", dict(default=cfg.get("base_url"))),
                     ("--api-key-env", dict(default=cfg.get("api_key_env", "OPENAI_API_KEY"))),
                     ("--scope", dict(default="SCOPE.yaml")), ("--out", dict(default="out/live_suite"))]:
        ls2.add_argument(flag, **kw)
    ls2.add_argument("--arg", action="append", default=[])
    ls2.add_argument("--gullible", action="store_true")
    ls2.add_argument("-n", type=int, default=3, help="trials per attack/task pair")

    px = sub.add_parser("proxy", help="recording stdio proxy for any MCP client (use after `--`: the server command)")
    px.add_argument("--server", required=True)
    px.add_argument("--scope", default="SCOPE.yaml")
    px.add_argument("--transcript")
    px.add_argument("--inject-json")
    px.add_argument("server_cmd", nargs="+", help="server command and args")

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

    rs = sub.add_parser("rescore", help="re-judge stored traces with the current oracle (no model calls)")
    rs.add_argument("results", help="a results.json from an earlier run")
    rs.add_argument("--out", default="out/rescored")

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

    if a.cmd == "enumerate":
        if not Path(a.scope).exists():
            raise SystemExit(f"refused: {a.scope} not found; a scope file is required (see SCOPE.example.yaml)")
        try:
            gate = Gate(load_scope(a.scope))
            tools = enumerate_server(gate, a.server, a.command, a.arg, a.timeout)
        except ScopeError as e:
            raise SystemExit(f"invalid scope file {a.scope}: {e}")
        except OutOfScope as e:
            raise SystemExit(f"refused: {e}")
        except TimeoutError:
            raise SystemExit(f"error: server '{a.server}' did not respond within {a.timeout}s")
        if a.json:
            print(json.dumps(tools, indent=2))
            return
        res = scan_manifest(tools)
        print(json.dumps({"server": a.server, "tools": inventory(tools), **res}, indent=2))
        raise SystemExit(1 if any(f["severity"] == "high" for f in res["findings"]) else 0)

    if a.cmd == "monitor":
        if not Path(a.scope).exists():
            raise SystemExit(f"refused: {a.scope} not found; a scope file is required (see SCOPE.example.yaml)")
        try:
            tools = enumerate_server(Gate(load_scope(a.scope)), a.server, a.command, a.arg, a.timeout)
        except ScopeError as e:
            raise SystemExit(f"invalid scope file {a.scope}: {e}")
        except OutOfScope as e:
            raise SystemExit(f"refused: {e}")
        except TimeoutError:
            raise SystemExit(f"error: server '{a.server}' did not respond within {a.timeout}s")
        pins_path = Path(a.pins)
        if not pins_path.exists() or a.update:
            report = check(json.loads(pins_path.read_text()), tools) if pins_path.exists() else None
            pins_path.write_text(json.dumps(pin(tools), indent=2))
            if report:
                print(json.dumps(report, indent=2))
            print(f"baseline written: {len(tools)} tools -> {a.pins}")
            return
        report = check(json.loads(pins_path.read_text()), tools)
        print(json.dumps(report, indent=2))
        if report["changes"]:
            print(f"DRIFT: {len(report['changes'])} tool(s) changed since pinned", file=sys.stderr)
            raise SystemExit(1)
        print(f"ok: {len(tools)} tools match {a.pins}")
        return

    if a.cmd == "live-suite":
        if not Path(a.scope).exists():
            raise SystemExit(f"refused: {a.scope} not found; a scope file is required (see SCOPE.example.yaml)")
        from .gateway.live import GULLIBLE_SYSTEM, LIVE_TASKS, SinkUnavailable, live_suite, suite_markdown
        try:
            gate = Gate(load_scope(a.scope))
            gate.check_server(a.server)
            check_run(gate, a.agent, a.base_url)
            attacks = load_attacks(a.attacks or str(LIVE_ATTACKS))
            for m in [m for m in a.mutators.split(",") if m]:
                attacks += [mutate(x, m) for x in load_attacks(a.attacks or str(LIVE_ATTACKS))]
            system = a.system or (GULLIBLE_SYSTEM if a.gullible else None)
            factory = make_agent_factory(a.agent, a.model, system, a.base_url, a.api_key_env)
            res = live_suite(gate, factory, a.server, a.command, a.arg, a.collaborator, attacks,
                             LIVE_TASKS, a.n, a.out)
        except ScopeError as e:
            raise SystemExit(f"invalid scope file {a.scope}: {e}")
        except OutOfScope as e:
            raise SystemExit(f"refused: {e}")
        except SinkUnavailable as e:
            raise SystemExit(f"error: {e}")
        Path(a.out, "results.json").write_text(json.dumps(res, indent=2))
        Path(a.out, "report.md").write_text(suite_markdown(res))
        o = res["overall"]
        print(f"live suite: {len(res['pairs'])} pairs x n={a.n}  delivered={o['delivered']}/{o['trials']} "
              f"({o['asr']:.0%}, CI {o['ci'][0]:.0%}-{o['ci'][1]:.0%})  errors={o['errors']}  "
              f"disagreements={o['disagreements']}  report={Path(a.out, 'report.md')}")
        if o["errors"]:
            print(f"WARNING: {o['errors']} trial(s) errored; errors are NOT counted as secure.")
        return

    if a.cmd in ("live-run", "proxy"):
        if not Path(a.scope).exists():
            raise SystemExit(f"refused: {a.scope} not found; a scope file is required (see SCOPE.example.yaml)")
        try:
            gate = Gate(load_scope(a.scope))
            gate.check_server(a.server)
            if a.cmd == "proxy":
                from .gateway.proxy import run_proxy
                raise SystemExit(run_proxy(a.server_cmd, a.transcript,
                                           json.loads(a.inject_json) if a.inject_json else None))
            check_run(gate, a.agent, a.base_url)
            from .gateway.live import (
                DEFAULT_PAYLOAD,
                GULLIBLE_SYSTEM,
                SinkUnavailable,
                injection_spec,
                live_run,
            )
            inject = injection_spec(a.inject, payload=a.payload or DEFAULT_PAYLOAD)
            system = a.system or (GULLIBLE_SYSTEM if a.gullible else None)
            factory = make_agent_factory(a.agent, a.model, system, a.base_url, a.api_key_env)
            res = live_run(gate, factory, a.server, a.command, a.arg, a.collaborator, inject, a.n, a.out)
        except ScopeError as e:
            raise SystemExit(f"invalid scope file {a.scope}: {e}")
        except OutOfScope as e:
            raise SystemExit(f"refused: {e}")
        except SinkUnavailable as e:
            raise SystemExit(f"error: {e}")
        out = Path(a.out) / "results.json"
        out.write_text(json.dumps(res, indent=2))
        print(f"live run: injection={a.inject} n={res['n']} canary_arrived={res['canary_arrived']} "
              f"({res['arrival_rate']:.0%}, CI {res['ci'][0]:.0%}-{res['ci'][1]:.0%}) "
              f"canary_read={res['canary_read']} canary_in_answer={res['canary_in_answer']} "
              f"oracle_success={res['oracle_success']} disagreements={res['oracle_disagrees_with_sink']} "
              f"errors={res['errors']}  results={out}")
        if res["errors"]:
            first = next(t["error"] for t in res["trials"] if t["error"])
            print(f"WARNING: {res['errors']}/{res['n']} trials errored; first error: {first.splitlines()[0]}")
            if res["errors"] == res["n"]:
                print("WARNING: every trial errored, so these numbers say nothing about the agent.")
                raise SystemExit(2)
        return

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

    if a.cmd == "rescore":
        old = json.loads(Path(a.results).read_text())
        result, summary = rescore(old)
        path = write_report(result, summary, a.out, f"{result.get('meta', {}).get('agent', 'run')}-rescored")
        print(f"rescored: exposure={summary['headline']}  utility={summary['baseline_utility']:.0%}  "
              f"false_alarm={summary['baseline_false_alarm']:.0%}  "
              f"unrequested_outbound={summary['baseline_unrequested_outbound']:.0%}  report={path}")
        return

    gate = None
    if Path(a.scope).exists():
        try:
            gate = Gate(load_scope(a.scope))
        except ScopeError as e:
            raise SystemExit(f"invalid scope file {a.scope}: {e}")
    try:
        server = check_run(gate, a.agent, a.base_url)
    except OutOfScope as e:
        raise SystemExit(f"refused: {e}")

    mutator_names = [m for m in a.mutators.split(",") if m]
    attacks = load_attacks(a.attacks)
    for m in mutator_names:
        attacks += [mutate(x, m) for x in load_attacks(a.attacks)]
    if a.dry_run:
        print(f"dry run: agent={a.agent} target={server or 'none (hermetic)'} "
              f"scope={gate.scope.name if gate else 'not needed'} attacks={len(attacks)} "
              f"tasks={len(TASKS)} n={a.n}; no calls made")
        return
    factory = make_agent_factory(a.agent, a.model, a.system, a.base_url, a.api_key_env)
    result = run_suite(factory, attacks, TASKS, a.n)
    result["meta"] = meta.collect(agent=a.agent, model=a.model, system_override=bool(a.system),
                                  n=a.n, attacks=attacks, mutators=mutator_names)
    result["meta"]["base_url"] = a.base_url
    summary = score(result, [t["name"] for t in BASE_TOOLS])
    path = write_report(result, summary, a.out, a.agent)
    print(f"exposure={summary['headline']}  utility={summary['baseline_utility']:.0%}  "
          f"errors={summary['errors']}  report={path}")
    if a.fail_above is not None and summary["headline"] > a.fail_above:
        raise SystemExit(1)