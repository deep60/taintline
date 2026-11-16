# Using tripwire in CI

## Exit codes
| command | 0 | 1 | 3 |
|---|---|---|---|
| `enumerate` | no high-severity static finding | a high finding | |
| `monitor` | no drift from the pins | any tool changed, added or removed | |
| `monitor --config` | every server unchanged | drift on any server | a server could not be checked |
| `audit` | nothing at or above `--fail-on` | a finding at or above `--fail-on` | a config could not be parsed |

For the GitHub Action (config audit on pull requests, scheduled rug-pull monitor) see
[GITHUB_ACTION.md](GITHUB_ACTION.md).
| `live-suite --fail-above N` | valid run, exposure <= N | exposure > N | run invalid: errors, incomplete baseline, baseline completion < 90%, or stopped by a budget |

An invalid run never passes: exit 3 means "this result is not evidence", not "secure".

## Budgets (live-suite)
`--max-trials N` refuses to start when the plan (`(attacks + 1) x tasks x n`) is larger. `--max-minutes` and
`--max-tokens` stop between trials, so a run can overshoot by one trial; the result is then invalid.
`--dry-run` prints the plan. Token counts come from the agent's own usage fields (Anthropic, OpenAI-compatible,
Ollama); a target that reports none counts as 0 tokens, so use `--max-minutes` as well.

## SARIF
`--sarif PATH` on `enumerate`, `monitor` and `live-suite`, or `tripwire sarif --scan/--drift/--live --out`.
Results anchor to `--artifact` (default `mcp-config.json`) because MCP findings live on a server's tool, not
in a source file; the real subject is in `logicalLocations`. Each result has a stable fingerprint.
Evidence strength maps to level: canary delivered = error; attacker contacted = warning; secret read = note.

Untested sketch for GitHub code scanning (SARIF is checked structurally by `validate_sarif`, but has not been
uploaded to GitHub by us):
```yaml
- run: uv run tripwire monitor --url http://127.0.0.1:8000/mcp --pins pins.json --sarif tripwire.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: tripwire.sarif }
  if: always()
```
