# M3 report: third-party MCP servers (2026-10-31)

Local copies only, installed into `third_party/` (gitignored) with `--only-binary :all:` / `--ignore-scripts`,
run against throwaway data (`/tmp/tw_sandbox`, an empty git repo `/tmp/tw_repo`), no credentials, stdio transport.
Reproduce with `docs/THIRD_PARTY.md`. Raw output: `out/m3/` (not committed).

| server | version | tools | static scan | pin + monitor, same release twice |
|---|---|---|---|---|
| `mcp-server-fetch` (PyPI) | 2026.10.28 | 1 (`fetch`) | 0 findings | no drift |
| `mcp-server-git` (PyPI) | 2026.10.28 | 12 | 0 findings | (see rug pull) |
| `@modelcontextprotocol/server-filesystem` (npm) | 2.1.0 | 14 (incl. `write_file`, `edit_file`, `move_file`) | 0 findings | no drift |

What "0 findings" means: none of the static poisoning patterns (hidden instructions, exfil destinations,
invisible characters) appear in these three servers' tool text. It does not show the scanner catches real
poisoning on a third-party server, only that it does not raise false alarms on these. Detection is shown on
the synthetic `poisoned` and `rugpull` servers (`tests/test_http.py`, `tests/test_labs.py`).

## Rug-pull monitoring on a real server
Pinned `mcp-server-git` 2026.10.10, then listed 2026.10.28 against those pins:

`DRIFT: 12 tool(s) changed since pinned (1 description+schema, 11 titles)`

- 11 tools: only the schema `title` annotations changed (for example `GitStatus` to `statusArguments`).
- 1 tool (`git_create_branch`): the description gained "or commit" and its schema changed.
- Verdict for this upgrade: benign, and a reviewer can see that from the field breakdown. A hash-only monitor
  would have said "12 modified" and nothing more. Titles are text the model sees, so the monitor still exits 1 on
  a titles-only change; the breakdown is there so it can be reviewed quickly, not skipped.

This is a genuine version-to-version definition change on a real server. It is not a malicious rug pull; no
third-party server here has done one. The in-session malicious variant (definition changes after the first
call) is shown on `lab/servers/rugpull_server.py` over Streamable HTTP.

## Not covered
- No agent was run against these servers: only `fetch` can reach out, and the scenarios that matter (an
  outbound tool plus private data) need the lab servers. A fetch-based run against a local page is a next step.
- Streamable HTTP was verified on lab servers in both protocol eras, not on a third-party HTTP server.
- No OAuth or remote hosted servers (out of scope by design).
