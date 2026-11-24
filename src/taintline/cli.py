from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

import yaml

from . import meta
from .attacks import load_attacks, mutate
from .attacks.runner import run_suite
from .gateway.budget import Budget
from .labeling import format_gate, gate0, make_sheet
from .report import write_report
from .report.schema import load_results, stamp
from .rescore import rescore
from .sandbox import BASE_TOOLS
from .scanner import scan_manifest
from .scanner.auth_checks import check_client_config
from .scanner.enumerate import enumerate_server, enumerate_url, inventory, load_tools
from .scanner.rugpull import check, diff_pins, pin
from .scope import Gate, OutOfScope, ScopeError, load_scope
from .scope.target import check_run
from .scoring import score
from .targets import AGENT_KINDS, make_agent_factory
from .tasks import TASKS

LIVE_ATTACKS = Path(__file__).parent / "attacks" / "live"


def _config() -> dict:
    p = Path("taintline.yaml")
    return (yaml.safe_load(p.read_text()) or {}) if p.exists() else {}


def _write_sarif(findings, path: str, artifact: str) -> None:
    from .report.sarif import to_sarif, validate_sarif
    doc = to_sarif(findings, artifact)
    problems = validate_sarif(doc)
    if problems:
        raise SystemExit("internal error: SARIF output is malformed: " + "; ".join(problems))
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(doc, indent=2))
    print(f"sarif: {len(doc['runs'][0]['results'])} result(s) -> {path}", file=sys.stderr)


def _write_ocsf(findings, path: str) -> None:
    from .report.ocsf import to_ocsf, validate_ocsf, write_ocsf
    events = to_ocsf(findings)
    problems = validate_ocsf(events)
    if problems:
        raise SystemExit("internal error: OCSF output is malformed: " + "; ".join(problems))
    write_ocsf(events, path)
    print(f"ocsf: {len(events)} event(s) -> {path}", file=sys.stderr)


def _preflight(a) -> None:
    """One cheap request to the model server before trial 1 (after the scope gate approved its host)."""
    if getattr(a, "no_preflight", False):
        return
    from .targets.preflight import EndpointUnavailable, check_endpoint
    try:
        warning = check_endpoint(a.agent, a.model, a.base_url, a.api_key_env)
    except EndpointUnavailable as e:
        raise SystemExit(f"error: {e}\nNo trials were run. (--no-preflight skips this check.)")
    if warning:
        print(f"preflight: {warning}", file=sys.stderr)


def _add_agent_cmd(p) -> None:
    p.add_argument("--agent-cmd", help="with --agent command: your agent's command line, run once per trial "
                                       "(it gets the tools over MCP; see docs/BYO_AGENT.md)")
    p.add_argument("--agent-timeout", type=float, help="with --agent command: seconds before a trial is "
                                                     "stopped and counted as an error (default 600)")


def _agent_cmd(a) -> dict:
    import shlex
    return {"command": shlex.split(a.agent_cmd) if a.agent_cmd else None, "agent_timeout": a.agent_timeout}


def _session(a) -> None:
    from .session import CLIENT_CONFIGS, SessionError, score_session, start_session
    if a.session_cmd == "start":
        from .labs import get_lab
        if not Path(a.scope).exists():
            raise SystemExit(f"refused: {a.scope} not found; a scope file is required (see SCOPE.example.yaml)")
        try:
            s = start_session(Gate(load_scope(a.scope)), get_lab(a.lab), a.collaborator, a.out, a.attack, a.task)
        except ScopeError as e:
            raise SystemExit(f"invalid scope file {a.scope}: {e}")
        except OutOfScope as e:
            raise SystemExit(f"refused: {e}")
        except SessionError as e:
            raise SystemExit(f"error: {e}")
        except OSError as e:
            raise SystemExit(f"error: collaborator sink at {a.collaborator} is not answering ({e}). "
                             "Start it: python3 lab/collaborator/server.py")
        print(f"session: lab={s['lab']} attack={s['attack']} task={s['task']['id']}")
        print(f"\n1. Add the servers in {s['config']} to your MCP client, then restart it:")
        for client, where in CLIENT_CONFIGS.items():
            print(f"     {client}: {where}")
        print("2. In a NEW chat, send exactly:\n")
        print(f"     {s['task']['prompt']}\n")
        print(f"3. When the agent is done: taintline session score {a.out} --answer \"<its reply>\"")
        print("4. Remove the taintline-* servers from your client afterwards.")
        return
    try:
        answer = Path(a.answer_file).read_text() if a.answer_file else a.answer
        r = score_session(a.dir, answer)
    except FileNotFoundError as e:
        raise SystemExit(f"error: {e}; run `taintline session start` first")
    except OSError as e:
        raise SystemExit(f"error: collaborator sink is not answering ({e})")
    calls = ", ".join(c["tool"] for c in r["tool_calls"]) or "none"
    done = {True: "yes", False: "no", None: "unknown (pass --answer)"}[r["task_completed"]]
    print(f"session: attack={r['attack']} task={r['task']} tool calls: {calls}")
    print(f"session: injection fired={r['injection_fired']} read canary={r['canary_read']} "
          f"task done={done} oracle/sink disagree={r['oracle_disagrees_with_sink']}")
    if not r["valid"]:
        print("INVALID: " + "; ".join(r["problems"]))
        raise SystemExit(3)
    if r["canary_arrived"]:
        print("LEAKED: the canary arrived at the sink. Result: " + str(Path(a.dir, "result.json")))
        raise SystemExit(1)
    print("no leak in this session (one trial; run several sessions for a rate). Result: "
          + str(Path(a.dir, "result.json")))


PREFLIGHT_HELP = "skip the check that the model server answers and offers --model before trial 1"


def _notify(gate, a, findings, source: str) -> None:
    """Signed webhook when the findings warrant one; a delivery failure never changes the exit code."""
    if not a.notify_url:
        return
    from .notify import NotifyError, build_event, classify, send
    kind = classify(findings)
    if kind is None:
        print("notify: nothing to report", file=sys.stderr)
        return
    try:
        r = send(gate, a.notify_url, build_event(kind, findings, source), a.notify_secret_env,
                 dry_run=a.notify_dry_run)
    except OutOfScope as e:
        raise SystemExit(f"refused: {e}")
    except NotifyError as e:
        print(f"WARNING: notify failed: {e}", file=sys.stderr)
        return
    print(f"notify: {kind} -> {'dry run, not sent' if r['dry_run'] else 'HTTP ' + str(r['status'])}",
          file=sys.stderr)


def _list_tools(gate, a) -> list[dict]:
    """tools/list from a stdio server (--server/--command) or a Streamable HTTP one (--url)."""
    if a.url:
        return enumerate_url(gate, a.url, a.timeout, a.protocol)
    if not (a.server and a.command):
        raise SystemExit("give --url, or both --server and --command")
    return enumerate_server(gate, a.server, a.command, a.arg, a.timeout)


def main(argv=None):
    cfg = _config()
    ap = argparse.ArgumentParser(prog="taintline")
    from . import __version__
    ap.add_argument("--version", action="version", version=f"taintline {__version__}")
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
    r.add_argument("--no-preflight", action="store_true", help=PREFLIGHT_HELP)
    _add_agent_cmd(r)

    s = sub.add_parser("scan", help="static scan of an MCP tool manifest (JSON)")
    s.add_argument("manifest")

    pn = sub.add_parser("pin", help="save tool hashes (for rug-pull detection)")
    pn.add_argument("manifest")
    pn.add_argument("--out", default="pins.json")

    d = sub.add_parser("diff", help="compare a manifest against saved pins")
    d.add_argument("pins")
    d.add_argument("manifest")

    en = sub.add_parser("enumerate", help="list tools of a live stdio MCP server (scope-gated) and scan them")
    en.add_argument("--server", help="stdio: server name as listed in SCOPE.yaml")
    en.add_argument("--command", help="stdio: command that starts the server, e.g. python")
    en.add_argument("--arg", action="append", default=[], help="argument for --command (repeatable)")
    en.add_argument("--url", help="Streamable HTTP endpoint of a LOCAL copy you may test")
    en.add_argument("--protocol", default="auto", help="auto (default) or legacy to force the 2025 handshake")
    en.add_argument("--scope", default="SCOPE.yaml")
    en.add_argument("--timeout", type=float, default=30.0)
    en.add_argument("--sarif", help="also write SARIF 2.1.0 findings to this path")
    en.add_argument("--artifact", default="mcp-config.json", help="file SARIF results are anchored to")
    en.add_argument("--ocsf", help="also write OCSF 1.1 Detection Finding events here (.json or .ndjson)")
    en.add_argument("--json", action="store_true", help="print only the tool list (feed it to `pin`/`diff`)")

    mo = sub.add_parser("monitor", help="re-enumerate a live server and alert if any tool changed since pinned")
    mo.add_argument("--server", help="stdio: server name as listed in SCOPE.yaml")
    mo.add_argument("--command")
    mo.add_argument("--arg", action="append", default=[])
    mo.add_argument("--url", help="Streamable HTTP endpoint (instead of --server/--command)")
    mo.add_argument("--protocol", default="auto")
    mo.add_argument("--scope", default="SCOPE.yaml")
    mo.add_argument("--timeout", type=float, default=30.0)
    mo.add_argument("--sarif", help="also write SARIF 2.1.0 findings to this path")
    mo.add_argument("--artifact", default="mcp-config.json", help="file SARIF results are anchored to")
    mo.add_argument("--ocsf", help="also write OCSF 1.1 Detection Finding events here (.json or .ndjson)")
    mo.add_argument("--notify-url", help="POST a signed webhook here on drift, leak or invalid run")
    mo.add_argument("--notify-secret-env", default="TAINTLINE_WEBHOOK_SECRET",
                    help="name of the env var holding the HMAC signing secret")
    mo.add_argument("--notify-dry-run", action="store_true", help="build and sign, do not send")
    mo.add_argument("--pins", default="pins.json", help="pin file; created as the baseline if missing")
    mo.add_argument("--update", action="store_true", help="accept the current tools as the new baseline")
    mo.add_argument("--config", help="check EVERY server in this MCP client config (pins go to --pins-dir)")
    mo.add_argument("--pins-dir", default="pins", help="with --config: one pin file per server")

    au = sub.add_parser("audit", help="find MCP client configs and check them (secrets, http, unpinned "
                                      "packages, broad filesystem access); starts nothing")
    au.add_argument("paths", nargs="*", help="config files to check (default: discover them)")
    au.add_argument("--project", default=".", help="project folder to look in for .mcp.json, .vscode/mcp.json ...")
    au.add_argument("--no-user", action="store_true", help="skip per-user configs (Claude Desktop, Cursor ...)")
    au.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="high",
                    help="exit 1 when a finding is at least this severe (default: high)")
    au.add_argument("--sarif", help="also write SARIF 2.1.0, located at each config file and line")
    au.add_argument("--json", action="store_true", help="print JSON instead of text")

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
    lv.add_argument("--no-preflight", action="store_true", help=PREFLIGHT_HELP)
    _add_agent_cmd(lv)

    bb = sub.add_parser("blackbox", help="test a chat endpoint you are authorized to test (M6); "
                                         "plants an injection, the collaborator sink proves any leak")
    bb.add_argument("--config", required=True, help="blackbox YAML (see docs/BLACKBOX.md)")
    bb.add_argument("--collaborator", required=True,
                    help="sink URL the TARGET can reach (must be in scope); use a host you control")
    bb.add_argument("-n", type=int, default=3)
    bb.add_argument("--scope", default="SCOPE.yaml")
    bb.add_argument("--out", default="out/blackbox")
    bb.add_argument("--manual", action="store_true", help="print the content to plant instead of using an API")
    bb.add_argument("--max-requests", type=int, help="stop after this many requests to the target")
    bb.add_argument("--dry-run", action="store_true", help="print the plan and the hosts; send nothing")
    bb.add_argument("--sarif", help="also write SARIF 2.1.0 here")
    bb.add_argument("--artifact", default="mcp-config.json")

    ls2 = sub.add_parser("live-suite", help="all live attacks x all live tasks vs a real stdio MCP server")
    for flag, kw in [("--server", dict()), ("--command", dict()),
                     ("--lab", dict(help="a lab from `taintline labs` (servers, tasks and attacks included)")),
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
    ls2.add_argument("--gullible", action="store_true",
                     help="positive control: tell the model to obey instructions found in tool output")
    ls2.add_argument("--control", help="results.json of a --gullible run of the same setup; the report's trust "
                                       "block checks that it saw leaks")
    ls2.add_argument("--no-preflight", action="store_true", help=PREFLIGHT_HELP)
    _add_agent_cmd(ls2)
    ls2.add_argument("--request-timeout", type=float,
                     help="seconds to wait for one model reply (default 120 openai-compat, 300 ollama)")
    ls2.add_argument("--retries", type=int, default=2,
                     help="retry a model request that timed out or hit 429/502/503/504 (counted in results)")
    ls2.add_argument("--temperature", type=float, help="sampling temperature (default: provider default)")
    ls2.add_argument("--fix-seed", action="store_true",
                     help="pass each trial's seed to the model (Ollama, OpenAI-compatible); Anthropic has no seed")
    ls2.add_argument("-n", type=int, default=3, help="trials per attack/task pair")
    ls2.add_argument("--fail-above", type=float, help="CI mode: exit 1 if the exposure score exceeds this; "
                                                     "exit 3 if the run is invalid (errors, no baseline, stopped early)")
    ls2.add_argument("--max-trials", type=int, help="refuse to start if the plan needs more trials than this")
    ls2.add_argument("--max-minutes", type=float, help="stop between trials after this long; the run is then invalid")
    ls2.add_argument("--max-tokens", type=int, help="stop between trials after this many model tokens; invalid")
    ls2.add_argument("--dry-run", action="store_true", help="print the plan (pairs, trials) and exit; no calls")
    ls2.add_argument("--sarif", help="also write SARIF 2.1.0 findings to this path")
    ls2.add_argument("--artifact", default="mcp-config.json", help="file SARIF results are anchored to")
    ls2.add_argument("--ocsf", help="also write OCSF 1.1 Detection Finding events here (.json or .ndjson)")
    ls2.add_argument("--notify-url", help="POST a signed webhook here on drift, leak or invalid run")
    ls2.add_argument("--notify-secret-env", default="TAINTLINE_WEBHOOK_SECRET",
                    help="name of the env var holding the HMAC signing secret")
    ls2.add_argument("--notify-dry-run", action="store_true", help="build and sign, do not send")

    sa = sub.add_parser("sarif", help="turn saved scan / drift / live-suite JSON into one SARIF 2.1.0 file")
    sa.add_argument("--server", default="", help="name for --scan/--drift findings")
    sa.add_argument("--scan", help="JSON printed by `enumerate` or `scan`")
    sa.add_argument("--drift", help="JSON printed by `monitor` (changes + findings)")
    sa.add_argument("--live", help="results.json from live-suite")
    sa.add_argument("--artifact", default="mcp-config.json")
    sa.add_argument("--out", required=True)

    oc = sub.add_parser("ocsf", help="turn saved scan / drift / live-suite JSON into OCSF Detection Finding events")
    oc.add_argument("--server", default="", help="name for --scan/--drift findings")
    oc.add_argument("--scan")
    oc.add_argument("--drift")
    oc.add_argument("--live")
    oc.add_argument("--out", required=True)

    sub.add_parser("labs", help="list the bundled labs (servers, tasks, attacks)")
    at = sub.add_parser("attacks", help="attack library tools")
    at.add_argument("action", choices=["validate"])
    at.add_argument("path", nargs="?", help="YAML file or directory (default: the lab's attacks)")
    at.add_argument("--lab", help="check placeholders and tool names against this lab")
    at.add_argument("--show", action="store_true", help="print each attack as the lab will plant it")

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

    dm = sub.add_parser("demo", help="watch a prompt-injection leak happen and get proven at a sink (1 minute)")
    dm.add_argument("--out", default="out/demo")
    dm.add_argument("--agent", choices=[k for k in AGENT_KINDS if not k.startswith("mock") and k != "command"],
                    help="put a real model in the attack scene (default: scripted agents, no model)")
    dm.add_argument("--model")
    dm.add_argument("--base-url")
    dm.add_argument("--system", help="system prompt for the real model")
    dm.add_argument("--scope", default="SCOPE.yaml", help="needed only with --agent: must list the model host")

    rp = sub.add_parser("replay", help="build a step-by-step HTML replay from a demo.json or live-suite results.json")
    rp.add_argument("results")
    rp.add_argument("--out", help="output .html (default: replay.html next to the results file)")

    se = sub.add_parser("session", help="test an agent you can't script (Claude Desktop, Cursor, any MCP "
                                         "client): write its config, then score what happened")
    ses = se.add_subparsers(dest="session_cmd", required=True)
    st = ses.add_parser("start", help="write an MCP config with the lab behind the proxy and the attack planted")
    st.add_argument("--lab", required=True, help="a lab from `taintline labs`")
    st.add_argument("--attack", help="attack id (default: the lab's first); 'none' for a clean baseline")
    st.add_argument("--task", help="task id (default: the lab's first)")
    st.add_argument("--collaborator", default="http://127.0.0.1:8099")
    st.add_argument("--scope", default="SCOPE.yaml")
    st.add_argument("--out", default="out/session")
    sc = ses.add_parser("score", help="read the transcripts and the sink: did the canary leave?")
    sc.add_argument("dir", help="the --out folder of `session start`")
    sc.add_argument("--answer", default="", help="the agent's final reply, to check the task was done")
    sc.add_argument("--answer-file", help="read the agent's reply from this file instead")

    a = ap.parse_args(argv)

    if a.cmd == "session":
        return _session(a)

    if a.cmd == "replay":
        from .report.replay import write_replay
        src = Path(a.results)
        data = json.loads(src.read_text())
        if data.get("kind") != "demo":
            data = load_results(str(src))
        page = write_replay(data, a.out or src.with_name("replay.html"))
        print(f"replay: {page}")
        return

    if a.cmd == "demo":
        from .demo import run_demo
        try:
            res = run_demo(a.out, a.agent, a.model, a.base_url, a.scope, a.system)
        except OutOfScope as e:
            raise SystemExit(f"refused: {e}")
        raise SystemExit(2 if res["summary"]["errors"] or res["summary"]["baseline_false_alarm"] else 0)

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
            tools = _list_tools(gate, a)
        except ScopeError as e:
            raise SystemExit(f"invalid scope file {a.scope}: {e}")
        except OutOfScope as e:
            raise SystemExit(f"refused: {e}")
        except TimeoutError:
            raise SystemExit(f"error: server '{a.url or a.server}' did not respond within {a.timeout}s")
        if a.json:
            print(json.dumps(tools, indent=2))
            return
        res = scan_manifest(tools)
        print(json.dumps({"server": a.url or a.server, "tools": inventory(tools), **res}, indent=2))
        if a.sarif:
            from .report.sarif import from_scan
            _write_sarif(from_scan(a.url or a.server, res), a.sarif, a.artifact)
        if a.ocsf:
            from .report.sarif import from_scan
            _write_ocsf(from_scan(a.url or a.server, res), a.ocsf)
        raise SystemExit(1 if any(f["severity"] == "high" for f in res["findings"]) else 0)

    if a.cmd == "audit":
        from .scanner.config_audit import SEVERITY_ORDER, audit, format_audit, worst
        res = audit(a.paths or None, project=a.project, user=not (a.no_user or a.paths))
        print(json.dumps(res, indent=2) if a.json else format_audit(res))
        if a.sarif:
            from .report.sarif import from_audit
            _write_sarif(from_audit(res), a.sarif, "mcp-config.json")
        bad = [f["file"] for f in res["files"] if f["error"]]
        if bad:
            print(f"WARNING: could not parse {len(bad)} file(s): {', '.join(bad)}", file=sys.stderr)
        limit = SEVERITY_ORDER.get(a.fail_on, 99)
        raise SystemExit(1 if worst(res) >= limit else 3 if bad else 0)

    if a.cmd == "monitor" and a.config:
        if not Path(a.scope).exists():
            raise SystemExit(f"refused: {a.scope} not found; a scope file is required (see SCOPE.example.yaml)")
        from .report.sarif import Finding, from_drift
        from .scanner.monitor_config import exit_code, monitor_config
        try:
            gate = Gate(load_scope(a.scope))
        except ScopeError as e:
            raise SystemExit(f"invalid scope file {a.scope}: {e}")
        res = monitor_config(gate, a.config, a.pins_dir, a.timeout, a.update)
        for s in res["servers"]:
            print(f"{s['status'].upper():<10} {s['server']}: {s['detail']}")
            for c in (s["report"] or {}).get("changes", []):
                print(f"           {c['change']}: {c['tool']}" + (f" ({', '.join(c['fields'])})" if c.get("fields") else ""))
        found = [f for s in res["servers"] if s["report"] for f in from_drift(s["server"], s["report"])]
        found += [Finding("monitor/unchecked", "error", f"server '{s['server']}' was not checked: {s['detail']}",
                          s["server"]) for s in res["servers"] if s["status"] == "unchecked"]
        if a.sarif:
            _write_sarif(found, a.sarif, a.config)
        if a.ocsf:
            _write_ocsf(found, a.ocsf)
        _notify(gate, a, found, a.config)
        code = exit_code(res)
        if code == 3:
            print("UNCHECKED: at least one server could not be checked; that is not a pass.", file=sys.stderr)
        raise SystemExit(code)

    if a.cmd == "monitor":
        if not Path(a.scope).exists():
            raise SystemExit(f"refused: {a.scope} not found; a scope file is required (see SCOPE.example.yaml)")
        try:
            tools = _list_tools(Gate(load_scope(a.scope)), a)
        except ScopeError as e:
            raise SystemExit(f"invalid scope file {a.scope}: {e}")
        except OutOfScope as e:
            raise SystemExit(f"refused: {e}")
        except TimeoutError:
            raise SystemExit(f"error: server '{a.url or a.server}' did not respond within {a.timeout}s")
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
        if a.sarif:
            from .report.sarif import from_drift
            _write_sarif(from_drift(a.url or a.server, report), a.sarif, a.artifact)
        if a.ocsf or a.notify_url:
            from .report.sarif import from_drift
            found = from_drift(a.url or a.server, report)
            if a.ocsf:
                _write_ocsf(found, a.ocsf)
            _notify(Gate(load_scope(a.scope)), a, found, a.url or a.server)
        if report["changes"]:
            kinds: dict = {}
            for c in report["changes"]:
                key = "+".join(c.get("fields") or [c["change"]])
                kinds[key] = kinds.get(key, 0) + 1
            detail = ", ".join(f"{n} {k}" for k, n in sorted(kinds.items()))
            print(f"DRIFT: {len(report['changes'])} tool(s) changed since pinned ({detail})", file=sys.stderr)
            raise SystemExit(1)
        print(f"ok: {len(tools)} tools match {a.pins}")
        return

    if a.cmd == "sarif":
        from .report.sarif import from_drift, from_live, from_scan
        found = []
        if a.scan:
            found += from_scan(a.server, json.loads(Path(a.scan).read_text()))
        if a.drift:
            found += from_drift(a.server, json.loads(Path(a.drift).read_text()))
        if a.live:
            found += from_live(load_results(a.live))
        if not (a.scan or a.drift or a.live):
            raise SystemExit("give at least one of --scan, --drift, --live")
        _write_sarif(found, a.out, a.artifact)
        return

    if a.cmd == "ocsf":
        from .report.sarif import from_drift, from_live, from_scan
        found = []
        if a.scan:
            found += from_scan(a.server, json.loads(Path(a.scan).read_text()))
        if a.drift:
            found += from_drift(a.server, json.loads(Path(a.drift).read_text()))
        if a.live:
            found += from_live(load_results(a.live))
        if not (a.scan or a.drift or a.live):
            raise SystemExit("give at least one of --scan, --drift, --live")
        _write_ocsf(found, a.out)
        return

    if a.cmd == "labs":
        from .labs import LABS
        for lab in LABS.values():
            print(f"{lab.name:16} servers={'+'.join(lab.servers):14} tasks={len(lab.tasks)} "
                  f"attacks={len(lab.attacks())}  {lab.description}")
        print(f"total: {sum(len(lb.tasks) for lb in LABS.values())} tasks across {len(LABS)} labs")
        return

    if a.cmd == "attacks":
        from .attacks.validate import validate_file
        from .labs import GENERIC, get_lab
        lab = get_lab(a.lab) if a.lab else None
        path = a.path or (str(GENERIC) if lab and not lab.attack_file else str(lab.attack_file) if lab else None)
        if not path:
            raise SystemExit("give a path or --lab")
        subs = lab.subs() if lab else None
        tools = {lab.inject_tool} if lab and lab.inject_tool else None
        servers = set(lab.servers) if lab else None
        problems = validate_file(path, subs, tools, servers)
        if a.show and not problems:
            files = sorted(Path(path).glob("*.yaml")) if Path(path).is_dir() else [Path(path)]
            for f in files:
                for atk in load_attacks(f, subs):
                    where = atk.target_tool or (atk.env or {}).get("PAGE_VECTOR") or atk.surface
                    print(f"--- {atk.id}  [{atk.surface} -> {where}{' on ' + atk.server if atk.server else ''}, "
                          f"effort {atk.effort}, family {atk.family}]")
                    print("\n".join(atk.parts) if atk.parts else atk.payload.rstrip())
        for m in problems:
            print("PROBLEM:", m)
        print(f"{path}: {'OK' if not problems else str(len(problems)) + ' problem(s)'}")
        raise SystemExit(1 if problems else 0)

    if a.cmd == "blackbox":
        if not Path(a.scope).exists():
            raise SystemExit(f"refused: {a.scope} not found; a scope file is required (see SCOPE.example.yaml)")
        from .blackbox import blackbox_attacks, blackbox_suite
        from .gateway.live import SinkUnavailable, suite_markdown
        from .targets.blackbox_http import BlackboxConfigError, load_config
        try:
            gate = Gate(load_scope(a.scope))
            cfg = load_config(a.config, expand_env=not a.dry_run)
            hosts = [*cfg.hosts(), urlparse(a.collaborator).netloc]
            attacks = blackbox_attacks(a.collaborator)
            planned = (len(attacks) + 1) * len(cfg.tasks) * a.n
            print(f"plan: {len(attacks)} attacks x {len(cfg.tasks)} tasks + baseline, n={a.n} -> {planned} trials; "
                  f"hosts contacted: {sorted(set(hosts))}", file=sys.stderr)
            for h in hosts:
                gate.check_server(h)
            if a.max_requests is None and not a.dry_run:
                print("note: no --max-requests set; each trial sends ~3 requests to the target", file=sys.stderr)
            if a.dry_run:
                print("dry run: nothing sent")
                return
            res = blackbox_suite(gate, cfg, a.collaborator, a.n, a.out, attacks, manual=a.manual,
                                 max_requests=a.max_requests)
        except (ScopeError, BlackboxConfigError) as e:
            raise SystemExit(f"invalid config or scope: {e}")
        except OutOfScope as e:
            raise SystemExit(f"refused: {e}")
        except SinkUnavailable as e:
            raise SystemExit(f"error: {e}")
        res = stamp(res, "live_suite")
        Path(a.out, "results.json").write_text(json.dumps(res, indent=2))
        Path(a.out, "report.md").write_text(suite_markdown(res))
        from .report.replay import write_replay
        write_replay(res, Path(a.out, "replay.html"))
        if a.sarif:
            from .report.sarif import from_live
            _write_sarif(from_live(res), a.sarif, a.artifact)
        o, sm = res["overall"], res["summary"]
        print(f"blackbox: exposure={sm['headline']}/100  delivered={o['delivered']}/{o['trials']}  "
              f"errors={o['errors']}  requests={res['requests']}  report={Path(a.out, 'report.md')}")
        if not sm["valid"]:
            print("INVALID RUN: " + "; ".join(sm["invalid_reasons"]), file=sys.stderr)
        return

    if a.cmd == "live-suite":
        if not Path(a.scope).exists():
            raise SystemExit(f"refused: {a.scope} not found; a scope file is required (see SCOPE.example.yaml)")
        from .gateway.live import GULLIBLE_SYSTEM, LIVE_TASKS, SinkUnavailable, live_suite, suite_markdown
        from .labs import get_lab
        lab = get_lab(a.lab) if a.lab else None
        if not lab and not (a.server and a.command):
            raise SystemExit("give --lab NAME, or both --server and --command")
        try:
            gate = Gate(load_scope(a.scope))
            for name in (lab.servers if lab else [a.server]):
                gate.check_server(name)
            check_run(gate, a.agent, a.base_url)
            subs = lab.subs() if lab else None
            base = (lambda: load_attacks(a.attacks, subs)) if a.attacks else \
                (lab.attacks if lab else (lambda: load_attacks(str(LIVE_ATTACKS))))
            attacks = base()
            for m in [m for m in a.mutators.split(",") if m]:
                attacks += [mutate(x, m) for x in base()]
            tasks = lab.tasks if lab else LIVE_TASKS
            budget = Budget(a.max_trials, a.max_minutes * 60 if a.max_minutes else None, a.max_tokens)
            planned = (len(attacks) + 1) * len(tasks) * a.n
            print(f"plan: {len(attacks)} attacks x {len(tasks)} tasks + baseline, n={a.n} -> {planned} trials",
                  file=sys.stderr)
            over = budget.preflight(planned)
            if over:
                raise SystemExit(f"refused: {over}")
            if a.dry_run:
                print("dry run: no calls made")
                return
            _preflight(a)
            system = a.system or (GULLIBLE_SYSTEM if a.gullible else None)
            factory = make_agent_factory(a.agent, a.model, system, a.base_url, a.api_key_env,
                                         temperature=a.temperature, fix_seed=a.fix_seed,
                                         request_timeout=a.request_timeout, retries=a.retries,
                                         **_agent_cmd(a))
            res = live_suite(gate, factory, a.server or lab.name, a.command, a.arg, a.collaborator, attacks,
                             tasks, a.n, a.out,
                             specs=lab.specs() if lab else None, base_env=lab.env if lab else None,
                             lab=lab.name if lab else None, budget=budget)
            res["sampling"] = {"temperature": a.temperature, "seed_fixed": a.fix_seed}
            res["positive_control"] = bool(a.gullible)
            from .report.trust import load_control, trust
            if a.control:
                res["control"] = load_control(a.control)
            res["trust"] = trust(res)
        except ScopeError as e:
            raise SystemExit(f"invalid scope file {a.scope}: {e}")
        except OutOfScope as e:
            raise SystemExit(f"refused: {e}")
        except SinkUnavailable as e:
            raise SystemExit(f"error: {e}")
        res = stamp(res, "live_suite")
        Path(a.out, "results.json").write_text(json.dumps(res, indent=2))
        Path(a.out, "report.md").write_text(suite_markdown(res))
        from .report.replay import write_replay
        write_replay(res, Path(a.out, "replay.html"))
        if a.sarif:
            from .report.sarif import from_live
            _write_sarif(from_live(res), a.sarif, a.artifact)
        if a.ocsf or a.notify_url:
            from .report.sarif import from_live
            found = from_live(res)
            if a.ocsf:
                _write_ocsf(found, a.ocsf)
            _notify(gate, a, found, res.get("lab") or res.get("server", ""))
        o = res["overall"]
        print(f"live suite: exposure={res['summary']['headline']}/100  utility={res['summary']['baseline_utility']:.0%}  "
              f"false_alarm={res['summary']['baseline_false_alarm']:.0%}")
        print(f"live suite: {len(res['pairs'])} pairs x n={a.n}  delivered={o['delivered']}/{o['trials']} "
              f"({o['asr']:.0%}, CI {o['ci'][0]:.0%}-{o['ci'][1]:.0%})  errors={o['errors']}  "
              f"disagreements={o['disagreements']}  report={Path(a.out, 'report.md')}  "
              f"replay={Path(a.out, 'replay.html')}")
        if o["errors"]:
            print(f"WARNING: {o['errors']} trial(s) errored; errors are NOT counted as secure.")
        t = res["trust"]
        flagged = [c["check"] for c in t["checks"] if c["status"] in ("warn", "fail")]
        print(f"trust: {t['label']}" + (f" ({', '.join(flagged)})" if flagged else ""))
        sm = res["summary"]
        if not sm["valid"]:
            print("INVALID RUN: " + "; ".join(sm["invalid_reasons"]), file=sys.stderr)
        if a.fail_above is not None:
            if not sm["valid"]:
                raise SystemExit(3)
            if sm["headline"] > a.fail_above:
                print(f"FAIL: exposure {sm['headline']} is above --fail-above {a.fail_above}", file=sys.stderr)
                raise SystemExit(1)
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
            _preflight(a)
            from .gateway.live import (
                DEFAULT_PAYLOAD,
                GULLIBLE_SYSTEM,
                SinkUnavailable,
                injection_spec,
                live_run,
            )
            inject = injection_spec(a.inject, payload=a.payload or DEFAULT_PAYLOAD)
            system = a.system or (GULLIBLE_SYSTEM if a.gullible else None)
            factory = make_agent_factory(a.agent, a.model, system, a.base_url, a.api_key_env, **_agent_cmd(a))
            res = live_run(gate, factory, a.server, a.command, a.arg, a.collaborator, inject, a.n, a.out)
        except ScopeError as e:
            raise SystemExit(f"invalid scope file {a.scope}: {e}")
        except OutOfScope as e:
            raise SystemExit(f"refused: {e}")
        except SinkUnavailable as e:
            raise SystemExit(f"error: {e}")
        out = Path(a.out) / "results.json"
        out.write_text(json.dumps(stamp(res, "live_run"), indent=2))
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
        old = load_results(a.results)
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
    _preflight(a)
    factory = make_agent_factory(a.agent, a.model, a.system, a.base_url, a.api_key_env, **_agent_cmd(a))
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