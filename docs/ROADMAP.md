# Roadmap: from today's prototype to the pitch

Pitch: *red team for AI agents and their tool integrations (MCP servers, browser agents,
copilots) with prompt injection, tool poisoning and data-leak chains, scored by exposure.*

Status today (2026-10-30): agents + real stdio MCP servers work with sink-confirmed leaks,
a baseline and a positive control. Everything else in the pitch is partial or missing.
Order below follows dependencies: trust the measurement first, widen coverage second,
add new target types last.

Each milestone has an **exit check** that must be shown with real output before moving on.

---

## M0. Housekeeping (half a day)
- Commit current work in logical pieces (see `docs/BUILD_GUIDE.md` Step 2); add `.DS_Store` to `.gitignore`.
- Keep `out/` data out of source commits (separate "run data" commit, or `.gitignore` large runs).

**Exit:** `git status` clean; tests green.

## M1. Trust the live measurement (1 week)
Why first: every later number depends on it.
1. **Delivered vs attempted.** Oracle must not count a tool call that returned an error
   (seen in the positive control: trial 10 "succeeded" with a rejected `recipient` arg).
   Report `attempted` and `delivered`; headline = sink-confirmed delivered.
2. **Argument-name tolerance is the agent's problem, not ours**, but log tool errors per trial.
3. **Gate G0 on live traces:** blind-label 30+ live traces (default + gullible runs), run `gate0`,
   fill in `docs/oracle_validation.md`.
4. **Bigger n:** rerun default, baseline and gullible with n=30 on llama3.1 and gpt-oss:20b.
5. **Single exposure score for live runs** (reuse `scoring/exposure.py` inputs: effort, severity,
   leak rate), with the report writer producing `report.md` for live runs.

**Exit:** G0 passes with documented precision/recall; live report with score and CIs for 2 models.

## M2. Real attack coverage on the live path (1-2 weeks)
1. **Plug the attack library into live runs.** Map each chain's `surface` to an MCP injection
   point (tool result, tool description, resource/prompt text) instead of the fake tools.
2. **Lab servers (stdio, canary data only):** files, email inbox, web fetch (with a local
   page server), key-value/db, and one deliberately poisoned server.
3. **Tasks:** 15+ benign tasks across those servers, each with an allowed-tools set and success keywords.
4. **Data-leak chains:** multi-step (read secret → encode → send), cross-server (read on A, exfil via B),
   delayed payload (injection arrives in turn 2), split payload, shadowed tool names.
5. **Mutators on the live path** (base64, homoglyph, zero-width) with the oracle's encoded-leak gap closed
   (decode before matching; known gap in `docs/oracle_validation.md`).
6. **Attack validator:** `tripwire attacks validate` so contributors add YAML without code.

**Exit:** 40+ attack/task pairs run live; coverage table in the report; no false alarms on baseline.

### M2 status (2026-10-30)
Built and tested (157 tests green):
- **Labs** (`tripwire labs`): 6 labs, 18 tasks, stdio servers in `lab/servers/` (`files`, `inbox`, `web`,
  `db`, `poisoned`, plus `notes`). Two are cross-server (`files+inbox`, `db+web`: read on A, exfiltrate via B),
  one pairs a deliberately poisoned server with a mailbox (`poisoned+inbox`, clean twin via `POISON=0` for the baseline).
- **Attack library on the live path**: `attacks/templates/generic.yaml` is filled per lab (10-11 attacks per lab:
  6 persuasion styles, tool-description poisoning, base64 and hex chains, delayed payload, split payload).
  Run with `tripwire live-suite --lab NAME`; `--mutators` still applies.
- **Chains**: multi-step (read, transform, send), cross-server, delayed (`after: N`), split (`parts: [...]`).
- **Encoded-leak detection**: the oracle and the sink match base64, hex, URL-encoding, ROT13, reversal,
  zero-width and separator-padded canaries; closes the known gap in `docs/oracle_validation.md`.
- **Attack validator**: `tripwire attacks validate [PATH] [--lab NAME]`.
- **`fired` column**: reports whether the injection was actually planted, so a delayed or split payload
  on a task that calls the tool once is flagged instead of read as "secure".

Not done yet (do not claim these):
- Shadowed tool names: `MultiSandbox` implements and tests the collision rule, but no lab attack uses it.
- Coverage table in the report (which surface x chain x server combinations ran) and the "40+ pairs at n>=10" run.
- Tasks are still hand-written keyword checks; the encoded-leak rule has not been through G0 labeling.
- The label sheet and `gate0` assume the notes lab; check them once on a cross-server result.

## M3. Real third-party MCP servers (1 week)
1. **Streamable HTTP** client and proxy (stdio is done). Read the current spec text first; support the
   current and previous revision, fail loudly on unknown.
2. Run against 3 open-source servers you did not write (e.g. reference filesystem, fetch, git).
   Always inside the scope gate, local copies only, never someone else's hosted instance.
3. Static scan + pin + monitor on each; record findings.
4. Safety: run servers with a throwaway working directory and no real credentials; document it in the threat model.

**Exit:** report for 3 third-party servers; one rug-pull demo on a real server.

### M3 status (2026-10-31)
Built and tested: Streamable HTTP client (`gateway/client.py::connect_url`, the SDK's `Client` negotiates the
current stateless 2026-07-28 revision and falls back to the 2025 session-based ones), a recording and
injecting HTTP proxy (`gateway/proxy_http.py`, loopback only, forwards to one upstream, redacts auth headers),
`MCPSandbox(url=...)`, `enumerate --url` / `monitor --url`, a local rug-pull server, and tests over real HTTP
for both protocol eras. Runbook: `docs/THIRD_PARTY.md`.
Done on real servers (`docs/M3_REPORT.md`): enumerate, static scan, pin and monitor on `mcp-server-fetch`,
`mcp-server-git` and `@modelcontextprotocol/server-filesystem`; a real version-to-version drift
(`mcp-server-git` 2026.10.10 to 2026.10.28: 12 tools changed, 11 titles only, 1 description+schema), now reported
per field. Pins store per-part hashes; older pin files still load.
Not done: no agent run against a third-party server, no third-party server over HTTP, no malicious rug pull in
the wild (the malicious variant is the lab `rugpull` server), no OAuth for remote servers.

## M4. Scores and reports (3-4 days)
- `schema_version` in `results.json`; SARIF 2.1.0 output; `--fail-above` for CI on live runs.
- One report format covering: static findings, rug-pull drift, dynamic leak rates, partial effects, coverage.
- Cost/token budget guard and fixed seeds/temperature where the target supports it.

**Exit:** SARIF accepted by GitHub code scanning on a sample repo.

## M5. Browser agents (2-3 weeks)
Cheap route: a browser agent is an agent with a browser **MCP server** (e.g. Playwright MCP).
1. Lab web server serving local pages: benign page, page with hidden injection (CSS-hidden text, HTML
   comment, alt text, form fields, markdown image exfil URL).
2. Task: "open page X and summarize"; same canary + sink pipeline; oracle unchanged.
3. Attack classes: hidden-text injection, link-following to attacker page, auto-submitted forms,
   image-URL exfiltration, cookie/localStorage canary.
4. Network isolation so the browser can only reach the lab and the sink.

**Exit:** browser-agent run with sink-confirmed leak and a clean baseline.

## M6. Copilots / black-box targets (later; needs a design partner)
- Implement `targets/blackbox_http.py` for chat endpoints you are authorized to test (scope-gated).
- The hard part is an **injection channel**: copilots read documents, email, tickets. Without a way to plant
  content where the copilot reads it, you can only test direct prompts.
- Do not build this until someone gives you a real target and written authorization.

**Exit:** one authorized copilot tested, with a written scope and a report the owner accepts.

## M7. Ship and sell (parallel from now)
- Name decision (trademark conflict), package + `uv build`, README with a 15-minute quickstart,
  PyPI release, GitHub Action.
- 30 customer conversations starting now (script in `docs/PLAN.md` section 6). If nobody offers a real
  server or agent to test, revisit scope before M5/M6.
- Narrow public wording to what is demonstrable until M5/M6 land.

---

## Rules while building
1. Every network path passes `scope.Gate`.
2. No LLM judge. Success needs sink-confirmed evidence; partial effects are reported separately.
3. A baseline and a positive control accompany every new attack family.
4. Errors are counted and never treated as "secure".
5. A new capability ships with tests and one real run recorded under `out/`.

## Rough timeline (part-time)
M0 0.5d, M1 1w, M2 2w, M3 1w, M4 0.5w, M5 3w, M6 later, M7 ongoing: about 8-9 weeks to a credible
v0.1 covering agents, MCP and browser agents.
