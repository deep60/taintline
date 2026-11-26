# Enterprise plan

Written 2026-11-17 from a scan of the repository. `docs/ROADMAP.md` tracks the milestones (M0 to M7);
this file is the order of work from a releasable CLI to a product enterprises can buy.

The open-source CLI is close to a releasable v0.1. The enterprise product has barely started: there is
no server, no history, no access control and no real customer run. Release and prove the CLI first,
then build the enterprise layer with design partners.

## Where the project stands (2026-11-17)

**Working and verified**
- Tests and lint: 311 passed, 1 skipped, ruff clean.
- Core engine: 21 CLI commands, 8 labs with 24 tasks, sink-proven leaks with no LLM judge, baselines,
  positive controls, confidence intervals, budgets and a scope gate.
- MCP supply chain: enumerate, pin, monitor (rug-pull detection) and config audit for Claude Desktop,
  Claude Code, Cursor, VS Code and Windsurf.
- Outputs: SARIF, OCSF, signed webhooks, HTML replay, findings write-ups and a leaderboard.
- Packaging: a built 0.1.0 wheel, a Dockerfile, a GitHub Action, a release workflow and a Homebrew formula.

**Gaps**

| Gap | Detail |
|---|---|
| Unpushed work | The branch is 4 commits ahead of GitHub, 6 files are uncommitted (the preflight check), and GitHub `main` is at a very old commit. |
| Stale README | It says Streamable HTTP, SARIF and black-box are "not built yet"; all three exist. |
| G0 oracle validation | Passed once (2026-11-25): 30 labels, 0 mismatches, notes lab and one local model. Other labs, frontier models and encoded leaks still to label. |
| Release never run | `release.yml` and the Action have not run on GitHub; nothing is on PyPI. |
| Browser lab | A text model of a browser, not a real one (no Playwright MCP). |
| Black-box mode | Tested only against the local mock copilot. |
| Models tested | Small local models only. No results on frontier models, which are what enterprises deploy. |
| Users | No outside user has run it. |

Not checked: whether the browser lab has been run on a real model. The roadmap says no, but a
hidden-text finding exists in `docs/findings`.

## Phase 0: Release (1 week)
1. Commit the preflight work, push the branch and merge to `main`.
2. Rewrite the README's "What works today" section to match reality.
3. Finish G0: label 30+ traces, run `gate0`, fill in `docs/oracle_validation.md`.
4. Set up PyPI trusted publishing, tag `v0.1.0`, confirm the release workflow and the Action run on GitHub.
5. Trademark and domain check for "Taintline".

**Exit:** `uv tool install taintline && taintline demo` works on a clean machine.

## Phase 1: Credibility with enterprise buyers (weeks 2 to 6)
1. **Frontier-model benchmark.** Run the suite on Claude, GPT and Gemini through their APIs and publish it.
2. **Real browser agent.** Repeat the browser attacks against a real Playwright MCP server.
3. **Real agent frameworks.** Targets for LangGraph, OpenAI Agents SDK, Bedrock Agents and Copilot Studio.
   Enterprises test their own agent, not a lab one.
4. **Adaptive attacker.** Mutate the payload after a failed attempt; the judge stays deterministic.
5. **Signed evidence bundles.** Transcript, hashes, seed and sink log, so an auditor can replay a finding.
6. **SARIF uploaded to GitHub code scanning** on a sample repo (the unmet M4 exit check).

**Exit:** a public benchmark page with reproducible numbers on at least 3 frontier models.

## Phase 2: Design partners (weeks 4 to 12, overlapping)
1. Talk to 30 security or AI-platform teams; aim for 5 pilots (script in `docs/PLAN.md`).
2. Pilot kit: authorization letter template, scope template, one-day runbook, sample report.
3. Run black-box mode on one real, authorized copilot (the M6 exit check).
4. Write down what every partner asks for. That list sets the order of Phase 3.

**Exit:** 3 partners have run it on their own agents and one says they would pay.

## Phase 3: Enterprise platform (months 3 to 6, only after Phase 2)
Self-hosted first: enterprises will not send agent transcripts to a new vendor's cloud.

| Piece | What it does |
|---|---|
| Server and database | Stores runs, findings and tool pins over time; shows trends and regressions. |
| Scheduler | Continuous tests and monitors per agent or MCP server. |
| Dashboard | Exposure score per agent, drift alerts, replay. |
| Access control | SSO (SAML/OIDC), roles, audit log. |
| API and CI gates | Blocks a deploy when the leak rate crosses a threshold. |
| Policy gateway | Turns the existing proxy into runtime blocking of tainted exfiltration and drifted tools. |
| Reports | Evidence packs mapped to OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF and ISO 42001. |

Check the exact control wording with a compliance person before selling on it.

**Exit:** one paying customer running it on a schedule.

## Phase 4: Enterprise readiness of the company (months 5 to 9)
- **Supply chain:** signed releases, an SBOM, a dependency and vulnerability policy.
- **Deployment:** air-gapped install, Helm chart, documented data-handling policy.
- **Procurement:** SOC 2 Type I, a security questionnaire pack, a support SLA, a commercial licence alongside MIT.
- **Coverage growth:** RAG poisoning, memory poisoning, multi-agent chains, an MCP registry scanning feed.

## What enterprises will ask
- **"Does it work on our agent?"** Phase 1 framework targets and Phase 2 pilots.
- **"Can we trust the numbers?"** G0 validation and evidence bundles. This is the main advantage; finish G0 first.
- **"Where does our data go?"** Self-hosted first, with the scope gate.
- **"Does it fit our tools?"** SARIF, OCSF and webhooks exist. Validate them against a real SIEM.

## What not to build yet
- A hosted SaaS, multi-tenancy and SCIM, until partners ask.
- More lab servers or attack YAML; coverage is not the bottleneck.
- `dual_era.py` and other stubs, unless a user needs them.

## The rule
Release, then frontier-model results, then partners, then the platform. Building Phase 3 before anyone
outside has used the CLI is the biggest risk in this plan.
