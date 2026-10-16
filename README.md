# Tripwire

Red team for AI agents and their MCP tool integrations. Plants prompt injection and tool
poisoning in a sandbox of fake tools with canary secrets, decides success with
deterministic oracles, and reports attack success rate with confidence intervals plus a
decomposed exposure score.

    uv sync
    uv run pytest -q
    uv run python -m tripwire run --agent mock-naive -n 20 --out out/naive
    uv run python -m tripwire run --agent anthropic --model <MODEL> -n 3 --out out/real
    uv run python -m tripwire scan examples/poisoned_manifest.json

## Read before trusting any number
- `mock-*` agents are NOT models; they only prove the harness works.
- `--agent anthropic` is UNTESTED against the live API.
- Scoring weights are assumptions. Attack/task coverage is tiny.
- `gateway/client.py`, `proxy.py`, `dual_era.py`, `scanner/enumerate.py::enumerate_server`,
  `report/sarif.py`, `targets/blackbox_http.py` are stubs (NotImplementedError).
- `lab/docker-compose.yml` and `.github/workflows/ci.yml` are untested.
- Only test systems you own or are authorized to test. See THREAT_MODEL.md.
