# agent-tripwire (MVP skeleton)

Attacks AI tool-using agents with prompt injection and tool poisoning inside a sandbox of
fake tools and canary secrets, decides success with deterministic oracles, and reports
attack success rate with confidence intervals plus a decomposed exposure score.

    pip install pyyaml pytest anthropic
    python -m tripwire run --agent mock-naive -n 20 --out out/naive
    python -m tripwire run --agent anthropic --model <MODEL_NAME> -n 20 --out out/real
    python -m tripwire scan examples/poisoned_manifest.json
    pytest

## Read this before trusting any number
- `mock-*` agents are NOT models. They exist to prove the harness works. Their scores mean nothing about real agents.
- `--agent anthropic` is written but UNTESTED against the live API.
- Score weights (scorer.py) are assumptions, uncalibrated.
- Only 5 attacks, 3 tasks, 5 tools. This is a skeleton, not coverage.
- Only test agents you own or are authorized to test.

## Layout
sandbox.py (fake tools + canaries) · oracle.py (deterministic success) · attacks.py + attacks/library.yaml
· agents.py · runner.py (N trials, Wilson CI, benign baseline) · scorer.py · report.py · scanner.py (static MCP manifest scan)
