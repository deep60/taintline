# Changelog

All notable changes. Versions follow [Semantic Versioning](https://semver.org); before 1.0, a minor
version may change result formats (each results file carries its own `schema_version`).

## [0.1.0] - unreleased

First public release. (Developed as "Tripwire"; renamed before release.)

### Measure
- Live suites against real MCP lab servers (8 labs, 24 tasks), with leaks proven only when a canary
  secret arrives at a collaborator sink. No LLM judge. Errors are counted, never treated as secure.
- Wilson confidence intervals, a clean baseline for false alarms and task completion, positive
  controls (`--gullible`), budgets, and invalid-run detection.
- Black-box mode for chat endpoints you're authorized to test; a scope gate on every network
  path and every process start.
- Model requests that time out, or hit 429/502/503/504, are retried with backoff
  (`--request-timeout`, `--retries`). Every retry is counted in the results.

### See it
- `dyepack demo`: watch a leak happen and get proven, with no model, key or network. Docker image
  included.
- `replay.html` for every run: where the injected text came in and where the secret left.
- Findings write-ups and a leaderboard, all generated from committed run snapshots.

### Guard
- `dyepack audit`: find MCP client configs (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf)
  and flag pasted secrets, plain http, unpinned server packages, broad filesystem access and
  auto-approved tools.
- `dyepack monitor --config`: rug-pull detection for every server in a config.
- GitHub Action for both, with SARIF on the config file's own line. OCSF export and signed webhooks.

### Contribute
- Attacks are YAML. Three starter attacks, `attacks validate --show`, and a CI gate over every lab.
