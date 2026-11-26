# Changelog

All notable changes. Versions follow [Semantic Versioning](https://semver.org); before 1.0, a minor
version may change result formats (each results file carries its own `schema_version`).

## [Unreleased]

### Added
- `--agent command --agent-cmd "..."`: test your own agent, not just a model. Each trial runs your
  command as a process and gives it the lab's tools over a local MCP endpoint (Streamable HTTP, or
  stdio through a shim). The sink still decides success, and the agent never sees the canary.
  Crashes and timeouts count as errors; exit 4 means the agent's turn limit. See
  [docs/BYO_AGENT.md](docs/BYO_AGENT.md) and [examples/byo_agent/agent.py](examples/byo_agent/agent.py).
  `--base-url` reaches the agent as `TAINTLINE_BASE_URL`. The local endpoint passes on
  `tools/list_changed` over its event stream, so rug-pull attacks reach command agents too.
- Every live-suite report now opens with **"Can you trust this result?"**: run complete, enough
  trials, no false alarms, the agent still does its job, no errors, attacks reached the agent,
  oracle agrees with sink, positive control, human validation of the oracle. Verdict: solid, read
  with care, or do not rely on it. Also saved as `trust` in results.json and printed after the run.
  Link a `--gullible` run with `--control PATH` so the positive-control check can pass.
- `taintline session start` / `session score`: test agents you can't script (Claude Desktop,
  Cursor, Claude Code). `start` writes an MCP config with the lab behind the recording proxy and
  the attack planted; you use the agent normally; `score` rebuilds the tool calls from the
  transcripts and asks the sink whether the canary arrived. See [docs/CLOSED_AGENTS.md](docs/CLOSED_AGENTS.md).
- `audit` finds the **lethal trifecta across servers**: private data, untrusted content and a way out
  spread over the servers one client loads (say filesystem + web search + a mailer), and single
  servers that have all three (GitHub, Slack, a mailbox). Servers are recognized from a catalog of
  well-known ones; unknown servers are left out, never guessed.
- Every finding that can be tested carries a **prove** command: a `taintline session` lab with the
  same shape (trifecta, poisoned description, shadowed tool, broad file access, auto-approval), or
  `monitor` for unpinned packages. Shown in text, JSON and SARIF.
- Three MCP-specific attack surfaces, in the notes lab and the generic templates for every lab:
  `tool_error` (one call fails with an error carrying the instruction), `tool_schema` (the
  instruction sits in a parameter's description) and `rug_pull` (the tool is clean until first use,
  then the server announces `tools/list_changed` and later listings carry the payload). The
  sandbox now re-lists tools when a server says they changed, as real clients do. The static
  scanner now reads parameter descriptions too. See [docs/ATTACKS.md](docs/ATTACKS.md).
- `taintline compare A B`: did a change really change the leak rate? Fisher's exact test overall
  and per attack, Holm-adjusted for testing many attacks at once. Says "not shown", never "no
  difference", when the evidence is thin, and carries over each run's trust verdict.
  `--fail-if-worse` exits 1 when B leaks significantly more, for CI.
- `live-suite --target FILE`: the full suite against your own MCP server (Streamable HTTP or
  stdio). The file names a canary you planted, the injection and outbound tools, and your tasks;
  attacks send to the sink's own URL so a leak can be proven. See [docs/TARGETS.md](docs/TARGETS.md).
- `--target-width W` picks `-n` so the overall 95% interval is at most W wide.
- `audit` flags package names that imitate well-known MCP packages: one or two characters off,
  or a scoped package's bare name, which anyone can own (`possible_typosquat`, `scope_confusion`;
  high). Offline, against a fixed list; a typo inside an owned scope isn't flagged, since it can't
  be published there.
- `session score` writes a step-by-step `replay.html` of the session.
- `taintline proxy` says what it is: a testing proxy, not a production gateway.
- Gate G0 passed: 30 hand-labeled traces from a real-model run matched the oracle on every row
  (notes lab, one local model). Reports say so under "Oracle checked by humans". See
  [docs/oracle_validation.md](docs/oracle_validation.md).

### Changed
- Tool capability detection (`scan`, trifecta checks) reads tool names as words and input-schema
  parameter names (`url`, `to`, `sql`, `path`) instead of matching substrings anywhere in the text.
  "http" in a description, or "note" in a tool's name, no longer counts as a capability. Each
  capability now comes with its reason (`evidence` in scan output). Checked on all 25 lab tools.

## [0.1.0] - 2026-11-24

First public release. (Developed as "Tripwire", briefly renamed "Dyepack"; renamed again before release.)

### Measure
- Live suites against real MCP lab servers (8 labs, 24 tasks), with leaks proven only when a canary
  secret arrives at a collaborator sink. No LLM judge. Errors are counted, never treated as secure.
- Wilson confidence intervals, a clean baseline for false alarms and task completion, positive
  controls (`--gullible`), budgets, and invalid-run detection.
- Black-box mode for chat endpoints you're authorized to test; a scope gate on every network
  path and every process start.
- Model requests that time out, or hit 429/502/503/504, are retried with backoff
  (`--request-timeout`, `--retries`). Every retry is counted in the results.
- Before trial 1, the model server is asked for its model list. A server that isn't running, or one
  that doesn't offer `--model`, stops the run at once instead of producing hundreds of errored
  trials (`--no-preflight` skips the check).

### See it
- `taintline demo`: watch a leak happen and get proven, with no model, key or network. Docker image
  included.
- `replay.html` for every run: where the injected text came in and where the secret left.
- Findings write-ups and a leaderboard, all generated from committed run snapshots.

### Guard
- `taintline audit`: find MCP client configs (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf)
  and flag pasted secrets, plain http, unpinned server packages, broad filesystem access and
  auto-approved tools.
- `taintline monitor --config`: rug-pull detection for every server in a config.
- GitHub Action for both, with SARIF on the config file's own line. OCSF export and signed webhooks.

### Contribute
- Attacks are YAML. Three starter attacks, `attacks validate --show`, and a CI gate over every lab.
