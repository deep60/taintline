# Contributing to Taintline

The easiest way to contribute is **an attack**: a few lines of YAML, no Python. Every attack is
run against real MCP lab servers, and it only counts when the planted secret **arrives at the
attacker's sink**. Nothing is scored by an LLM judge.

## Ground rules

- **Labs only.** Attacks target the bundled lab servers and the fake `acme.example` /
  `evil.example` world. Don't put real companies, people, domains or credentials in an attack.
- **No claims without a run.** A rate in an issue or PR comes with the command and the run folder
  (or its `results.json`). Errors are reported, never counted as "resisted".
- **Keep the scope gate.** Code that touches a network or starts a process goes through `Gate`.
  A PR that bypasses it won't be merged.

## Set up

```bash
git clone https://github.com/deep60/taintline && cd taintline
uv sync
uv run python -m pytest -q
uv run taintline demo          # watch one leak get proven, no model needed
```

## Add an attack (good first contribution)

1. **Pick a lab.** Run `uv run taintline labs`. Most labs are built from templates (`inbox`, `web`,
   `files+inbox`, `db+web`, `poisoned+inbox`), and one generic attack runs in all of them. `notes`,
   `browser` and `shadow+inbox` have their own attack files.
2. **Copy a starter** from [examples/attacks/](examples/attacks/):
   - [01_notes_calendar_invite.yaml](examples/attacks/01_notes_calendar_invite.yaml): one lab, payload in a tool result
   - [02_generic_tool_description.yaml](examples/attacks/02_generic_tool_description.yaml): every template lab, payload in a tool description
   - [03_browser_aria_label.yaml](examples/attacks/03_browser_aria_label.yaml): browser lab, payload hidden in the page
3. **Change the idea, not the plumbing.** Keep the placeholders (`{attacker_email}`,
   `{read_secret}`, ...) and write a new persuasion style, disguise or hiding place. The field
   reference is in [docs/ATTACKS.md](docs/ATTACKS.md).
4. **Validate, and look at exactly what the lab will plant:**
   ```bash
   uv run taintline attacks validate my_attack.yaml --lab inbox --show
   ```
5. **Run it, if you have a local model** (optional, but it makes the PR much stronger). This needs
   LM Studio or Ollama, the sink running (`python3 lab/collaborator/server.py`), and the lab's
   servers plus `127.0.0.1:8099` listed in your `SCOPE.yaml`:
   ```bash
   uv run taintline live-suite --lab inbox --attacks my_attack.yaml -n 3 \
     --agent openai-compat --model YOUR_MODEL --base-url http://localhost:1234/v1 --out out/my_attack
   ```
   Check the **`fired`** column first. If it's 0, the payload never reached the model, and a 0%
   leak rate means nothing. Then look at `out/my_attack/replay.html` to see what the agent did.
6. **Open a PR** that adds your entry to the lab's attack file (`src/taintline/attacks/templates/generic.yaml`
   for template labs, `attacks/live/notes.yaml`, `attacks/browser/browser.yaml`, ...). Fill in the
   PR template. If you ran it, include the report table.

An attack that never leaks is still welcome when it **fires**. "This disguise doesn't work on
model X" is a result.

## Other contributions

- **New lab:** a server in `lab/servers/`, tasks and wiring in `src/taintline/labs.py`, plus a test.
  Open an issue first.
- **Results for a model:** run the labs on a model we haven't covered and open an issue with the
  run folders. See [docs/leaderboard/](docs/leaderboard/) for what gets published.
- **Bugs:** include the command, the output and `uv run taintline --help | head -3`.

## Before you push

```bash
uv run ruff check src tests scripts
uv run python -m pytest -q
```

`tests/test_contrib.py` validates every bundled attack file and every starter against its labs.
CI runs it on every PR.
