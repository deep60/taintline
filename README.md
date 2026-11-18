# Taintline

Red team for AI agents and the MCP servers they connect to. Taintline plants prompt injection
and tool poisoning in what an agent reads, then decides success with **deterministic
checks, no LLM judge**: did a unique canary secret actually arrive at a sink you control?
It reports attack success with confidence intervals, a benign baseline (false alarms), and
counts errors instead of treating them as "secure".

> Status: working prototype (v0.1 in progress). Authorized testing only. Read
> [THREAT_MODEL.md](THREAT_MODEL.md) first.

## What works today

**Run on real models.** These have produced results with local models (RedSage 8B, gpt-oss 20B,
llama3.1) through LM Studio and Ollama. The numbers are in [docs/findings](docs/findings) and
[docs/leaderboard](docs/leaderboard).

| Capability | Command |
|---|---|
| See a leak happen and get proven, with no model, key or network | `taintline demo` |
| Every attack against every task on a real MCP lab server; a leak counts only when the canary reaches the sink | `taintline live-suite --lab NAME` (8 labs, 24 tasks: `taintline labs`) |
| One attack against your own stdio MCP server, through a recording proxy | `taintline live-run`, `taintline proxy` |
| Confidence intervals, a clean baseline for false alarms, positive controls, budgets, invalid-run detection | built into `live-suite` (`--gullible`, `--max-trials`, `--fail-above`) |
| Retries counted in the results; stops before trial 1 if the model server doesn't answer | `--request-timeout`, `--retries` |
| Step-by-step HTML replay of a run | `replay.html` in every run folder, `taintline replay` |
| Scope gate: refuses any host, server or process not in `SCOPE.yaml` | automatic |

**Built and tested, not yet proven in the field.** These pass their tests and were run locally,
but haven't been used on someone else's system or on GitHub yet.

| Capability | Command | not yet done |
|---|---|---|
| Find MCP client configs and flag pasted secrets, plain http, unpinned packages, broad filesystem access | `taintline audit` | — |
| Rug-pull detection: alert when a server's tools change | `taintline monitor`, `--config` for every server in a config | — |
| List and scan the tools of a stdio or Streamable HTTP server | `taintline enumerate`, `scan`, `pin`, `diff` | — |
| SARIF 2.1.0 and OCSF output, signed webhooks | `--sarif`, `taintline sarif`, `taintline ocsf`, `--notify-url` | upload to GitHub code scanning |
| GitHub Action for audit and monitor | [action.yml](action.yml), [docs/GITHUB_ACTION.md](docs/GITHUB_ACTION.md) | a run on GitHub |
| Black-box test of a chat endpoint you're authorized to test | `taintline blackbox` | a run on a real copilot |
| Check the oracle against human labels | `label-sheet`, `gate0`, `rescore` | 30 labels ([docs/oracle_validation.md](docs/oracle_validation.md)) |
| Docker image, PyPI package, release workflow | `docker run --rm --network none taintline`, [docs/RELEASE.md](docs/RELEASE.md) | first release |

**Not built:** frontier-model benchmarks (Claude, GPT, Gemini), a real browser MCP server
(the browser lab is simulated), targets for agent frameworks (LangGraph, OpenAI Agents SDK,
Bedrock), an adaptive attacker, and a server or dashboard. See
[docs/ENTERPRISE_PLAN.md](docs/ENTERPRISE_PLAN.md).

## Quickstart (about 10 minutes, local model, nothing leaves your machine)
```bash
uv sync
uv run python -m pytest -q                     # expect: all pass

cp SCOPE.example.yaml SCOPE.yaml               # then edit: list what you may test
```
`SCOPE.yaml`:
```yaml
name: my-lab
authorized_by: "your name"
servers:
  - notes                 # the lab MCP server
  - localhost:11434       # ollama
  - localhost:8099        # the collaborator sink
```

Terminal 1, the sink that records anything sent to it (stop with Ctrl-C, never Ctrl-Z):
```bash
python3 lab/collaborator/server.py
```
Terminal 2, a local model (`ollama pull llama3.1`):
```bash
ollama serve
```
Terminal 3:
```bash
# baseline: the agent doing its job, no attack. Expect 0 leaks.
uv run taintline live-run --server notes --command python --arg lab/servers/notes_server.py \
  --collaborator http://localhost:8099 --agent ollama --model llama3.1:latest -n 5 --inject none --out out/baseline

# positive control: a gullible prompt. Expect leaks; proves the pipeline can see them.
uv run taintline live-run --server notes --command python --arg lab/servers/notes_server.py \
  --collaborator http://localhost:8099 --agent ollama --model llama3.1:latest -n 10 --gullible --out out/control

# the full suite: every attack x every task, report in out/live_suite/report.md
uv run taintline live-suite --server notes --command python --arg lab/servers/notes_server.py \
  --collaborator http://localhost:8099 --agent ollama --model llama3.1:latest -n 3
```

## How to read a result
- **delivered** is attack success: the canary reached the sink. Nothing else counts.
- **read secret / in answer** are partial effects: the injection changed behavior, but nothing left.
- **failed attempts**: the agent tried to leak but the tool call errored.
- **errors** are agent/API failures. They are never counted as "secure".
- Small n gives wide intervals. At n=5, zero hits still allows a true rate up to about 43%.

## Watch a real MCP server for tampering
```bash
uv run taintline monitor --server notes --command python --arg lab/servers/notes_server.py
# first run writes pins.json; later runs exit 1 and list any tool whose definition changed
```

## Caveats
- `mock-*` agents are not models; they only prove the harness works.
- `--agent anthropic` is untested against the live API.
- Scoring weights are assumptions. The labs are small and simulated (8 labs, 24 tasks).
- The oracle has not yet been validated by human labeling (`docs/oracle_validation.md`).
- Results so far come from local 7–20B models only.
- Only test systems you own or are authorized to test.

More: [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md), [docs/PLAN.md](docs/PLAN.md), [docs/writing_chains.md](docs/writing_chains.md).
