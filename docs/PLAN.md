# Dyepack — Product Analysis & Startup Plan

**Date:** 27 Oct 2026
**Status:** pre-product / credible research prototype
**Goal:** turn this into a fundable, revenue-generating startup

---

## 0. TL;DR

You have built the **hard, honest part** of an agent-security product and skipped the
**easy, visible part**. The engineering discipline is genuinely above average for this
category: deterministic oracles, no LLM judge, baseline utility, false-alarm tracking,
Wilson intervals, run metadata pinning, attack-library hashing, default-deny scope gate.
Most "AI security" startups do not have that.

What you do **not** have:

1. **Any connection to a real MCP server.** The core claim ("MCP tool integrations") is
   a `NotImplementedError`. Right now the product tests a fake in-process sandbox with
   5 hardcoded tools.
2. **Enough coverage to be credible.** 5 attacks × 3 tasks = 7 pairs. A real assessment
   needs 50+ attacks and 20+ tasks minimum.
3. **A clean success oracle.** "Any outbound call = attack success" produces false
   positives (your own llama3.1 baseline shows a 40% false-alarm rate and a "successful
   attack" that is actually a benign call to `api.summarizer.com`).
4. **A product.** No PyPI package, no CLI entry point, no Docker image, no SARIF, no
   dashboard, no auth, no billing, no docs site.
5. **A name you can own.** "Tripwire" is an existing enterprise security trademark
   (Tripwire, Inc. / Fortra). This is a launch blocker, not a detail.

**Verdict:** strong prototype, wrong shape for a startup *as currently framed*. "Red team
for agents" is a feature and a crowded category. The defensible company hiding inside
this repo is **continuous trust/verification for the MCP supply chain** — scan, verify,
monitor, attest. Your existing modules (`scanner/`, `rugpull.py`, `gateway/hash.py`,
`report/`) are already the skeleton of that product.

**Recommended path:** open-source CLI for distribution → hosted continuous verification
for revenue → signed evidence reports for enterprise. Sell to AI platform teams and MCP
server vendors. Fund the first 6 months with fixed-scope assessments.

---

## 1. Product audit

### 1.1 Maturity scorecard

| Area | Score | Reality |
|---|---|---|
| Core harness design | 7/10 | Clean separation: targets / sandbox / attacks / oracles / scoring / report |
| Real-world applicability | 2/10 | No real MCP client; fake sandbox only |
| Attack coverage | 2/10 | 5 attacks, 3 tasks, 2 canary classes, 5 tools |
| Oracle rigor | 5/10 | Deterministic and honest, but success definition is too broad |
| Reproducibility / evidence | 7/10 | Metadata pinning, library hash, CIs, raw traces — rare and valuable |
| Productization | 2/10 | No entry point, PyPI, Docker, SARIF, dashboard, auth |
| Legal / safety posture | 4/10 | Scope gate exists but is **not wired into the run path**; THREAT_MODEL.md empty |
| GTM / distribution | 0/10 | No landing page, docs site, users, pricing, content |
| **Overall** | **prototype** | ~2,430 LOC, 81 tests passing, ruff clean |

### 1.2 What is genuinely good (do not throw away)

- **Deterministic oracles.** No LLM-as-judge. This is your credibility moat. Keep it.
- **Errors are counted, never treated as "secure."** `attacks/runner.py` + report warnings.
- **Benign baseline + false-alarm rate.** Almost nobody does this. It is the thing that
  makes your numbers defensible to a security buyer.
- **Reproducibility metadata.** `meta.py`: git SHA, library hash, model, N, date. This is
  the seed of an *evidence* product.
- **Default-deny scope gate.** `scope/` is well-designed (no wildcards, explicit
  `authorized_by`, `fuzz` flag). It is also your legal shield — once wired in.
- **Honest README caveats.** That culture is an asset; keep it in public docs.
- **Rug-pull pinning + tool hashing.** `gateway/hash.py` canonicalization is exactly the
  right primitive for supply-chain monitoring.

### 1.3 What is broken or missing (prioritized)

#### P0 — blocks any real customer

| # | Issue | Where | Why it matters |
|---|---|---|---|
| 1 | No real MCP connectivity | `gateway/client.py`, `proxy.py`, `dual_era.py`, `scanner/enumerate.py::enumerate_server` | The product cannot test a real agent. Everything else is hypothetical. |
| 2 | Oracle counts benign outbound calls as attack success | `oracles/__init__.py` | Inflates ASR, fails your own Gate G0, destroys trust with security buyers. |
| 3 | Coverage far too thin | `attacks/chains/`, `tasks.py` | 7 pairs cannot support a finding, let alone a report. |
| 4 | Scope gate not enforced in the run pipeline | `cli.py`, `attacks/runner.py` | Offensive tool without enforced authorization = legal and reputational risk. |
| 5 | Corrupted LICENSE | `LICENSE` | Trailing text is garbled ("CONTRALIABILITY…"). Looks unprofessional; may be legally defective. |
| 6 | Name conflict | repo name / package | Tripwire is a registered brand in security. You will lose the domain, SEO, and possibly a trademark dispute. |

#### P1 — blocks a paid product

| # | Issue | Where |
|---|---|---|
| 7 | No `[project.scripts]` entry point, so no `dyepack` command | `pyproject.toml` |
| 8 | No PyPI release, Docker image, or release CI | `.github/` |
| 9 | `THREAT_MODEL.md` is 0 bytes | root |
| 10 | README is stale vs. actual runs | `README.md` |
| 11 | No SARIF output / GitHub Action → no CI adoption path | `report/sarif.py` |
| 12 | Results schema is unversioned; reports will break between releases | `report/json_report.py` |
| 13 | No temperature/seed pinning on real targets → non-reproducible runs | `targets/*.py` |
| 14 | Sequential execution only; slow and expensive at scale | `attacks/runner.py` |
| 15 | No cost/token budget guard for real model runs | `targets/*.py` |
| 16 | Static scanner heuristics are naive (case-sensitive duplicate names, over-broad toxic-flow regex) | `scanner/` |
| 17 | Zero tests for the stubbed MCP path, by definition | `gateway/`, `scanner/enumerate.py` |

#### P2 — later

- Multi-turn attacks (the mutator docstring already admits this).
- Split-payload / cross-tool chains.
- Language switching.
- Black-box HTTP target (`targets/blackbox_http.py`) — correctly deferred.
- Telemetry / crash reporting (opt-in only).

---

## 2. Market reality check

### 2.1 Category

You are in three overlapping categories, and you must pick one to lead with:

1. **AI red teaming / LLM evaluation** — crowded, enterprise-sales-heavy.
   Players to verify current status: promptfoo, PyRIT, garak, Inspect AI, Mindgard,
   HiddenLayer, Lakera/Check Point, Protect AI/Palo Alto, Invariant/Snyk, Zenity,
   Noma, Aim, Straiker, Prompt Security, Knostic.
2. **MCP supply-chain security** — newer, less consolidated, closer to your code.
   Players: mcp-scan (Invariant/Snyk), Cisco mcp-scanner, Semgrep MCP rules,
   mcp-shield, and a long tail of GitHub scripts.
3. **Agent runtime guardrails** — biggest budget, but a different product (inline proxy
   that blocks actions). Do **not** start here.

**Pick #2 as the wedge, with #1 as the premium capability.** Reasons:

- The buyer problem is concrete and recurring: *"Which MCP servers can we safely connect
  to our agents, and did any of them change since we approved them?"*
- Your code already implements the primitives: manifest scan, tool hashing, rug-pull
  diff, config secret checks, deterministic dynamic verification.
- Distribution exists: MCP registries and directories are where these servers are
  discovered.
- It produces recurring revenue by nature (monitoring), unlike one-off pentests.

### 2.2 Why now (verify before you put it in a deck)

- MCP has become the default tool-integration protocol for agents, so "a tool changed
  after approval" is now a real supply-chain problem.
- Prompt injection / tool poisoning moved from research demos to production incidents.
- Compliance pressure around AI systems (EU AI Act timelines, ISO/IEC 42001, SOC 2
  vendor questionnaires) is creating demand for *evidence*, not just tooling.
- Security budgets are consolidating: buyers prefer one platform over five scanners.
  This is a threat to you *and* an argument for a narrow, high-signal product.

### 2.3 The gap you can own

> **Nobody credibly answers "is this MCP server safe to connect, and is it still the
> same server we approved?" with reproducible evidence.**

Static scanners answer "does the description contain suspicious text?" Dynamic red
teamers answer "can this model be jailbroken?" Neither answers the supply-chain question
with *proof* (canary actually arrived, tool hash actually changed, baseline utility
preserved). Your collaborator oracle + pinning + baseline design is uniquely positioned
here.

### 2.4 Naming

**Done (2026-11-17): renamed to Dyepack.** Originally: **rename before launch.** "Tripwire" collides with a well-known security brand. You need:
- a `.com` or `.dev` you can actually buy,
- a USPTO/EUIPO check in class 9/42,
- a GitHub org, PyPI name, and npm name,
- no confusion with file-integrity monitoring.

Shortlist directions (check availability yourself): `toolchain`, `mcpprobe`, `canarylayer`,
`trustwire`, `toolguard`, `pinned`, `serverproof`, `injectionlab`. Avoid generic
"AI security" words.

---

## 3. Positioning

### 3.1 One-liner (recommended)

> **Continuous security verification for the MCP servers your agents depend on.**
> Scan them, prove they resist tool poisoning, and get alerted when one silently changes.

### 3.2 Ideal customer profile (start narrow, in this order)

1. **AI platform / agent teams at Series A–C startups (20–300 people).** They ship agents
   fast, connect third-party MCP servers, have no dedicated AppSec, and feel the risk.
   Buyer: Head of Engineering / CTO. Fast decisions, low ACV, great for design partners.
2. **MCP server vendors / infrastructure companies.** They want a trust badge and a
   security page to win enterprise deals. Buyer: DevRel / founder. Small but strategic.
3. **Security teams at enterprises deploying agents.** Longer sales cycle, bigger ACV.
   Only go here after you have case studies and SOC 2 readiness.

**Anti-persona:** solo hobbyists, students, anyone who only wants a free scanner. They
are distribution, not revenue.

### 3.3 Product ladder (maps 1:1 to your modules)

| Tier | Product | Your code | Price |
|---|---|---|---|
| **Scan** (free, OSS) | Static manifest + client-config checks, CLI | `scanner/` | $0 |
| **Verify** (paid) | Dynamic red-team run in CI, SARIF, pass/fail gate | `attacks/`, `oracles/`, `scoring/`, `report/` | $99/mo per workspace |
| **Monitor** (paid, recurring) | Pin tool hashes, alert on rug-pull, scheduled re-verification | `scanner/rugpull.py`, `gateway/hash.py` | $299–$499/mo |
| **Attest** (enterprise) | Signed evidence report, run provenance, audit trail, self-hosted | `meta.py`, `report/`, hosted API | $25k+/yr |

This is the key strategic move: **the free scanner is your distribution, the recurring
monitor is your business, the evidence report is your margin.**

### 3.4 Growth loop (the part most founders miss)

1. Build **public MCP server report cards** from *passive, public* manifest data only.
   No active exploitation without authorization. (Legal review required.)
2. Server authors see their grade, fix issues, and **claim a badge** → they share it.
3. Platform teams search *"is `<server>` safe?"* → land on your page → convert to
   continuous monitoring.
4. Registries link to your report cards → permanent distribution.

Think SSL Labs / securityheaders.com, but for MCP servers. This is the cheapest,
most durable top-of-funnel available to you, and it compounds.

---

## 4. Business model

### 4.1 Pricing (start here, raise later)

| Plan | Price | Includes |
|---|---|---|
| OSS | $0 | CLI, unlimited local scans, 1 target, community support |
| Team | $99/mo | 5 monitored targets, CI + SARIF, 30-day history, email alerts |
| Growth | $499/mo | 25 targets, scheduled runs, evidence PDF, priority support |
| Enterprise | $25k–$75k/yr | Self-hosted, SSO/SCIM, DPA, audit logs, support SLA |
| Assessment | $7.5k–$15k | Fixed-scope manual agent/MCP security assessment (cash now) |
| Certification | later | Per-server verified badge, annual fee |

Benchmark check (verify): developer security tools typically land at $25–$100 per
developer/month; supply-chain platforms at $20k–$100k+/yr enterprise. Your pricing must
be anchored to *number of monitored servers/repos*, not seats — it scales with the
customer's exposure and is easy to justify.

### 4.2 Unit economics

- Biggest variable cost is model inference. Default to **BYOK** (bring your own key) for
  hosted runs, and use local models (Ollama) for the public benchmark.
- Target 80%+ gross margin. Keep per-run cost visible in the UI and capped by `--budget`.
- Never resell tokens at a loss to win deals.

### 4.3 Revenue sequencing

Months 1–3: **services** (assessments) → validates demand and funds development.
Months 3–6: **design-partner subscriptions** → product-market fit signal.
Months 6–12: **self-serve Team/Growth** → repeatable revenue.
Month 12+: **enterprise/attestation** → expansion revenue.

Do not build the cloud before 5 design partners are running the CLI weekly.

---

## 5. Technical completion plan

### 5.1 Target architecture

```
                    ┌──────────────────────────────┐
  agent / client ──▶│  MCP logging proxy (dyepack) │──▶ real MCP server
                    │  • records JSON-RPC           │
                    │  • injects payloads           │
                    │  • enforces scope gate        │
                    │  • rewrites outbound to sink  │
                    └──────────────┬───────────────┘
                                   │ traces + hashes
                    ┌──────────────▼───────────────┐
                    │  oracles (canary, sink, log) │
                    └──────────────┬───────────────┘
                                   │ verdicts
                    ┌──────────────▼───────────────┐
                    │ scoring → report → SARIF/PDF │
                    └──────────────────────────────┘
```

Design decision to make explicitly: **proxy-first**, not library-first. A proxy works
with any MCP client (Claude Desktop, Cursor, VS Code, custom agents), gives ground truth
on every message, and is the only architecture that scales to real customers. Your
in-process `Sandbox` stays as the fast, hermetic test fixture for the attack library.

### 5.2 Phase 0 — Credibility & scope freeze (week 1)

Goal: make the repo honest, safe, and shippable as v0.1.

- [ ] Decide the name; check trademark + domains + PyPI + GitHub org.
- [ ] Replace `LICENSE` (use Apache-2.0 if you want patent protection; add a
      `COMMERCIAL.md` note only if you plan open-core).
- [ ] Write `THREAT_MODEL.md`: assets, adversaries, trust boundaries, out-of-scope,
      authorization model, data handling, disclosure policy.
- [ ] Fix the oracle: `success` = canary leaked **or** attacker-controlled destination
      contacted **or** collaborator confirms arrival. Everything else is a separate
      `policy_violation` finding, not an attack success.
- [ ] Wire `scope.Gate` into `cli.py` and every connector; refuse to run without
      `SCOPE.yaml`. Add a `--dry-run` that never touches the network.
- [ ] Add `temperature=0` (where supported), `seed`, and a `--budget` token cap.
- [ ] Version the results schema (`schema_version`) and add a migration note.
- [ ] Update README to match reality; add "Status / not yet supported" matrix.
- [ ] Add `[project.scripts] dyepack = "dyepack.cli:main"`.
- [ ] Add `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`.
- [ ] Enable branch protection + required CI (ruff, pytest, pre-commit).
- [ ] Re-run Gate G0 on one real model and record the result in
      `docs/oracle_validation.md`.

**Exit criteria:** `dyepack run` against a real local MCP server, scope-gated, canary
proven at the collaborator, G0 passed, clean install from a fresh venv.

### 5.3 Phase 1 — Real MCP engine (weeks 2–4)

- [ ] Implement `gateway/client.py`: stdio + Streamable HTTP transports.
- [ ] Implement era detection (`dual_era.py`) from the **current spec text**, not memory.
      Support the current era and the previous one; fail loudly on unknown.
- [ ] Implement `scanner/enumerate.py::enumerate_server`: live `tools/list` with schemas.
- [ ] Implement `gateway/proxy.py`: transparent JSON-RPC proxy, full transcript,
      per-message tool hashing, payload injection hooks (description, result, schema).
- [ ] Build the lab: `docker-compose` with `lab` internal network, synthetic MCP servers
      (email, files, web, db, payments), collaborator sink, no egress.
- [ ] Rewrite `sandbox.Sandbox` as an adapter over a real MCP server, keeping the current
      in-process version as `HermeticSandbox` for tests.
- [ ] Replay/record mode so a run can be reproduced offline from a transcript.
- [ ] Tests: proxy passthrough, injection placement, scope refusal, transport failures,
      server timeout, malformed JSON-RPC.

**Exit criteria:** enumerate a third-party MCP server, run 25 attack trials through the
proxy, prove canary arrival at the sink, produce a report. Demo video recorded.

### 5.4 Phase 2 — Coverage & evidence (weeks 5–8)

- [ ] Attack library to **50+ attacks / 20+ tasks / 15+ pairs per run**:
      - direct + indirect prompt injection (email, web, file, ticket, doc)
      - tool poisoning (description, schema, `_meta`, annotations)
      - tool-result injection and delayed payloads
      - rug pull (post-approval mutation)
      - tool shadowing / duplicate names / namespace confusion
      - cross-tool exfiltration (lethal trifecta chains)
      - encoded variants (base64, homoglyph, zero-width, RTL, markdown image exfil)
      - SSRF, path traversal, confused deputy, token passthrough (authorized only)
      - multi-turn / split payload
- [ ] Attack contribution format + validator (`dyepack attacks validate`), so the
      community can add attacks without touching code.
- [ ] Oracle validation v2: 200+ human-labeled traces, report precision/recall/F1,
      publish the number. This is a marketing asset.
- [ ] Determinism suite: same seed + same model → same verdict within tolerance.
- [ ] Parallel trials with a worker pool; per-run cost estimate.
- [ ] SARIF 2.1.0 output + `--fail-above` semantics documented.
- [ ] GitHub Action (`dyepack/scan-action@v1`) with PR annotations and baseline diff.
- [ ] Benchmark v0: 5 models × 50 attacks, published with methodology + raw data.

**Exit criteria:** benchmark report published; SARIF accepted by GitHub code scanning;
oracle precision/recall documented; CI action used by 3 external repos.

### 5.5 Phase 3 — Productization & hosted (weeks 9–14)

- [ ] PyPI release + signed wheels + Docker image (`ghcr.io/...`).
- [ ] Hosted API: orgs, projects, targets, runs, artifacts, diffs over time.
- [ ] Dashboard: run list, trend lines, worst findings, evidence export.
- [ ] Auth: GitHub OAuth. Billing: Stripe (Team/Growth). Quotas + BYOK.
- [ ] Scheduled monitoring: re-scan on MCP server version change; alert on tool-hash drift.
- [ ] Signed evidence PDF: scope, method, coverage, results, CIs, limitations, provenance.
- [ ] Public report cards for MCP servers (passive data only) + claim/badge flow.
- [ ] Data handling: redaction of canaries/secrets, retention policy, encryption, DPA,
      sub-processor list.
- [ ] Docs site: quickstart, CI setup, attack authoring, scope/legal, FAQ.

**Exit criteria:** 3 design partners running weekly; first paid invoice; time-to-first-
value under 10 minutes; dashboard p95 < 2s.

### 5.6 Phase 4 — GTM & scale (months 4–6)

- [ ] 10 design partners, 3 public case studies.
- [ ] 2 conference talks + 1 data-driven report ("We tested 100 MCP servers").
- [ ] Registry/directory partnerships for report cards.
- [ ] SOC 2 Type I readiness; pen-test your own product.
- [ ] Self-hosted enterprise deployment (Helm/compose), SSO, audit logs.
- [ ] Hiring: first hire should be a security researcher / DevRel hybrid, not another
      backend engineer.

### 5.7 Definition of Done for v1.0

A stranger can, in under 15 minutes:

1. `pip install <name>` or `docker run`.
2. Point it at a real MCP server with a valid `SCOPE.yaml`.
3. Run 30 trials, get a report with CIs, baseline utility, and a verified exfiltration
   trace.
4. Fail a CI build on a threshold, and see the finding in the PR.
5. Re-run later and get an alert that a tool definition changed.

Plus: no false-positive attack successes on the benign baseline, every number has a
provenance record, and the docs state exactly what the tool cannot do.

---

## 6. Go-to-market plan

### 6.1 Validate before building (weeks 1–3)

Talk to **30 people**, not 5. Target: AI platform leads, MCP server maintainers, AppSec
engineers at agent-heavy companies.

Questions that produce signal (not compliments):

- "Which MCP servers are connected to your production agents right now? Who approved
  them?"
- "What would you do if one of them changed its tool description tomorrow?"
- "How do you currently decide a third-party tool is safe to connect?"
- "Have you had an injection or tool-poisoning incident? What happened?"
- "Who would sign off on buying this, and from what budget?"
- "What did you try already, and why did you stop?"

**Signal to continue:** 5+ people describe the problem unprompted, 3+ agree to a design
partner call, 1+ asks "can I pay you to do this now?"
**Signal to pivot:** people say "interesting" but nobody will give you a server or a
budget line.

### 6.2 Design partner program

- 6 weeks, free, 5–8 partners.
- Weekly 30-min call; they run it in their CI by week 3.
- In exchange: logo, testimonial, case study, and a paid conversion at the end.
- Give them the assessment for free, but make them do the work of integrating. That is
  the real signal.

### 6.3 Launch sequence

1. **Quiet alpha** (weeks 3–6): 5 design partners, no public launch.
2. **Open-source launch** (week 8): Show HN, r/mcp, r/netsec, MCP Discord, AI security
   newsletters. Lead with the *benchmark data*, not the tool.
3. **Report-card launch** (week 12): "We analyzed the 100 most popular MCP servers."
   This is the viral asset.
4. **Paid launch** (week 14): Team plan + CI action, with a free tier that is genuinely
   useful.

Content beats ads at this stage. Every post should contain a number nobody else has.

### 6.4 Channels, ranked

1. Open source + GitHub (compounding, credible).
2. MCP registries/directories + report cards (intent-driven traffic).
3. Data reports + conference talks (authority).
4. Security/newsletter partnerships (borrowed trust).
5. Cold outbound to AI platform leads (only after case studies exist).

---

## 7. Metrics

**Product:** weekly active repos, runs/week, time-to-first-finding, % runs with zero
errors, oracle precision/recall, attack-library growth, median run cost.

**Business:** design partners, activation (first successful run within 24h), Team→Growth
conversion, logo churn, NRR, ACV, CAC payback, pipeline from report cards.

**North star (pick one):** *verified agent/MCP configurations under continuous
monitoring.* It captures both value delivered and recurring revenue.

Targets for the first 6 months: 10 design partners, 3 paying, $5k MRR, 500 GitHub stars,
1 published benchmark, oracle precision ≥ 0.95.

---

## 8. Risks and kill criteria

| Risk | Likelihood | Mitigation |
|---|---|---|
| Incumbents bundle a free MCP scanner | High | Compete on *verified evidence + monitoring*, not scanning |
| Protocol churn breaks the proxy | High | Isolate transports; conformance tests; support 2 eras |
| False positives destroy trust | High | Fix oracle; publish precision/recall; benchmark baselines |
| Legal exposure from offensive testing | Medium | Scope gate enforced in code, ToS, authorization record, no third-party active testing |
| Name/trademark dispute | Medium | Rename now |
| Solo-founder bandwidth | High | Ruthless scope; services for cash; one ICP |
| Model behavior drift makes benchmarks noisy | Medium | Pin versions, temperature 0, report CIs, date-stamp everything |
| No buyer with budget | Medium | 30 interviews before Phase 3 |

**Kill / pivot criteria (be honest with yourself):**

- If after 30 interviews nobody will give you a real server to test → the problem is not
  painful enough; pivot to pure compliance evidence or go services-only.
- If after 8 weeks no design partner runs it twice → the workflow is wrong, not the code.
- If oracle precision < 0.9 after 200 labels → do not ship dynamic results; ship static
  + monitoring only.
- If cloud infra costs exceed 20% of revenue at 10 customers → fix packaging/BYOK first.

---

## 9. Next 14 days (concrete)

**Days 1–2**
- [ ] Pick 3 candidate names; check trademark, domains, PyPI, GitHub org.
- [ ] Fix `LICENSE`; write `THREAT_MODEL.md` (1 page is enough).
- [ ] Fix the oracle success definition + add regression tests for the llama3.1 false
      positive.

**Days 3–4**
- [ ] Wire `scope.Gate` into `cli.py`; add `--dry-run`; add `temperature=0` and `--budget`.
- [ ] Add `[project.scripts]`; `uv build`; install from wheel in a clean venv.
- [ ] Version the results schema; update README status matrix.

**Days 5–7**
- [ ] Start `gateway/client.py` (stdio first). Get `tools/list` from one local server.
- [ ] Stand up the lab compose stack with one synthetic MCP server + collaborator.
- [ ] Record a 2-minute demo: real server → attack → canary arrives → report.

**Days 8–10**
- [ ] 10 customer interviews booked and done.
- [ ] Draft the design-partner one-pager and the assessment offer ($7.5k fixed scope).

**Days 11–14**
- [ ] Finish 10 more interviews; write down the exact words customers use.
- [ ] Implement the proxy skeleton (record-only, no injection).
- [ ] Decide: name, license, ICP. Write them at the top of this file and stop revisiting.
- [ ] Re-run Gate G0 end-to-end and commit the evidence.

---

## 10. Decisions only you can make

1. **Name** — rename or accept the trademark risk?
2. **License** — MIT (max adoption) vs Apache-2.0 (patent grant) vs open-core?
3. **Wedge** — MCP supply-chain trust (recommended) vs generic agent red teaming?
4. **Time/budget** — full-time? runway? can you fund 6 months of development?
5. **Cofounder** — do you need a security-research or GTM partner?
6. **First market** — startups (fast, low ACV) vs enterprises (slow, high ACV)?

Answer these before Phase 1. Every week you delay the name decision costs you SEO,
community, and domain options.

---

## Appendix A — Repo action map

| File / area | Action |
|---|---|
| `gateway/client.py` | Implement stdio + Streamable HTTP MCP client |
| `gateway/proxy.py` | Transparent JSON-RPC proxy with record + inject |
| `gateway/dual_era.py` | Era detection from current spec |
| `scanner/enumerate.py` | Live `tools/list` via client |
| `sandbox.py` | Split into `HermeticSandbox` + `MCPSandbox` |
| `oracles/__init__.py` | Fix success semantics; add policy-violation class |
| `oracles/collaborator.py` | Wire into the run pipeline |
| `scope/gate.py` | Call from every connection path |
| `cli.py` | Add `scan --live`, `verify`, `monitor`, `budget`, `--dry-run` |
| `report/sarif.py` | SARIF 2.1.0 |
| `report/json_report.py` | `schema_version`, artifact manifest |
| `meta.py` | Add model params, cost, spec era, proxy version |
| `targets/*.py` | temperature=0, seed, budget, retry/backoff |
| `pyproject.toml` | `[project.scripts]`, urls, classifiers, license |
| `.github/workflows/` | test + lint + release + publish |
| `THREAT_MODEL.md` | Write it |
| `LICENSE` | Replace corrupted file |
| `README.md` | Status matrix + 15-minute quickstart |

## Appendix B — What not to build yet

- A dashboard before a real MCP run works.
- SARIF before the oracle is trustworthy.
- A black-box HTTP target.
- Multi-tenant auth/billing before 5 design partners.
- Your own model inference stack.
- A generic "AI security platform." Stay narrow.

---

*This plan is opinionated on purpose. Change it when customer evidence contradicts it,
not when it feels uncomfortable.*
