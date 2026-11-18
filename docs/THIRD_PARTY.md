# Testing third-party MCP servers (M3)

Rules: local copies only, never someone else's hosted instance; throwaway data; no real credentials;
every server name or host:port is listed in `SCOPE.yaml`; installs go in `third_party/` (gitignored),
never into the project venv.

## Install (isolated; scripts and source builds disabled)
```bash
mkdir -p third_party
uv venv third_party/fetch && uv pip install --python third_party/fetch/bin/python --only-binary :all: mcp-server-fetch==2026.10.28
uv venv third_party/git   && uv pip install --python third_party/git/bin/python   --only-binary :all: mcp-server-git==2026.10.28
npm install --prefix third_party/filesystem --ignore-scripts @modelcontextprotocol/server-filesystem@2.1.0
```
`--only-binary :all:` and `--ignore-scripts` stop the installers from executing package build or
install scripts. The servers themselves still run when started, so only run them from `taintline`
commands below, against throwaway data (`mkdir /tmp/tw_sandbox; git init /tmp/tw_repo`).

## Per server: enumerate, scan, pin, monitor
```bash
uv run taintline enumerate --server fetch --command third_party/fetch/bin/python --arg -m --arg mcp_server_fetch
uv run taintline enumerate --server git   --command third_party/git/bin/python   --arg -m --arg mcp_server_git --arg --repository --arg /tmp/tw_repo
uv run taintline enumerate --server fs    --command node --arg third_party/filesystem/node_modules/.bin/mcp-server-filesystem --arg /tmp/tw_sandbox
```
Add `fetch`, `git`, `fs` under `servers:` in `SCOPE.yaml`. Then `monitor --pins pins_<name>.json` with the
same flags: the first run writes the baseline, later runs fail with DRIFT if any definition changed.

## Rug pull on a real server
A rug pull is a definition that changes after you approved it. On a third-party server it happens at
upgrade time: pin the version you reviewed, install a newer (or older) release into a second directory, and
`monitor` against the first pins. If the two releases have identical definitions there is no drift to
report, and the report says so. The local `rugpull_server.py` shows the in-session variant (the
definition changes after the first tool call): `tests/test_http.py::test_rug_pull_is_caught_by_pin_and_monitor_over_http`.

## HTTP servers
`taintline enumerate --url http://127.0.0.1:PORT/mcp` and `monitor --url ...` speak Streamable HTTP, the
current stateless revision (2026-07-28) first, then the session-based 2025 revisions
(`--protocol legacy` forces the old handshake). The server's `host:port` goes in `SCOPE.yaml`.
