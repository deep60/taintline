# Tripwire

Red team for AI agents and the MCP servers they connect to. Tripwire plants prompt injection
and tool poisoning in what an agent reads, then decides success with **deterministic
checks, no LLM judge**: did a unique canary secret actually arrive at a sink you control?
It reports attack success with confidence intervals, a benign baseline (false alarms), and
counts errors instead of treating them as "secure".

> Status: working prototype (v0.1 in progress). Authorized testing only. Read
> [THREAT_MODEL.md](THREAT_MODEL.md) first.

## What works today
| Capability | Command |
|---|---|
| Scope gate: refuses any target not in `SCOPE.yaml` | automatic on every networked command |
| Hermetic harness with mock/real agents | `tripwire run` |
| List tools of a live stdio MCP server, scan them | `tripwire enumerate` |
| Rug-pull detection (tool changed since pinned) | `tripwire monitor`, `pin`, `diff` |
| Recording proxy with injection planting | `tripwire proxy` |
| Live attack on a real MCP server, leak proven at a sink | `tripwire live-run`, `live-suite` |
| Oracle validation workflow (human labels) | `label-sheet`, `gate0`, `rescore` |

Not built yet: Streamable HTTP transport, SARIF output, PyPI release, black-box HTTP target.

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
uv run tripwire live-run --server notes --command python --arg lab/servers/notes_server.py \
  --collaborator http://localhost:8099 --agent ollama --model llama3.1:latest -n 5 --inject none --out out/baseline

# positive control: a gullible prompt. Expect leaks; proves the pipeline can see them.
uv run tripwire live-run --server notes --command python --arg lab/servers/notes_server.py \
  --collaborator http://localhost:8099 --agent ollama --model llama3.1:latest -n 10 --gullible --out out/control

# the full suite: every attack x every task, report in out/live_suite/report.md
uv run tripwire live-suite --server notes --command python --arg lab/servers/notes_server.py \
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
uv run tripwire monitor --server notes --command python --arg lab/servers/notes_server.py
# first run writes pins.json; later runs exit 1 and list any tool whose definition changed
```

## Caveats
- `mock-*` agents are not models; they only prove the harness works.
- `--agent anthropic` is untested against the live API.
- Scoring weights are assumptions. Coverage is small: one lab server, 8 attacks, 3 tasks.
- The oracle has not yet been validated by human labeling (`docs/oracle_validation.md`).
- `lab/docker-compose.yml` and the CI workflow are untested.
- Only test systems you own or are authorized to test.

More: [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md), [docs/PLAN.md](docs/PLAN.md), [docs/writing_chains.md](docs/writing_chains.md).
