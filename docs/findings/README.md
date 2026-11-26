# Findings

Short write-ups of what Taintline measured. A leak counts only when the secret **arrives at the
attacker's sink**. No LLM judge decides anything, and errored trials are reported, never counted as
secure.

1. [Hidden text that isn't hidden](01-hidden-text.md): aria-labels and off-screen text reach a
   browser agent; `display:none` doesn't.
2. [A shadowed tool copies every email](02-shadowed-tool.md): a second server's `send_email`
   copied 15/15 messages to the attacker, and the agent's log looked normal every time.
3. [Same leak rate, opposite behaviour](03-local-models.md): two small local models leak at the same
   rate but fail in very different ways.
4. [It's the story, not the channel](04-tool-errors.md): a "fix this error" step leaked the secret
   45/45 times, whether it arrived as an MCP error or in a normal result.

## How the numbers are kept honest

- `data/` holds a snapshot of each run: per-pair counts only, with no transcripts and no canaries.
- `scripts/build_findings.py` builds every table and chart from those snapshots and writes them
  between the `<!-- tw:... -->` markers in each post. `--refresh` re-snapshots from `out/<run>/`.
- `tests/test_findings.py` fails if a post's numbers no longer match its snapshots.
- Every post ends with the exact commands that produced its runs.

```bash
uv run python scripts/build_findings.py
```
