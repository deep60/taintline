## What this changes

## Checklist
- [ ] `uv run ruff check src tests scripts` and `uv run python -m pytest -q` pass
- [ ] New attacks pass `taintline attacks validate <file> --lab <lab>` (CI checks this too)
- [ ] Labs only: no real companies, people, domains or credentials
- [ ] Any network or process access goes through the scope gate
- [ ] Any rate I quote comes with its command and run folder; errors are reported, not counted as secure

## Results (if you ran it)
<!-- paste the report table from out/<run>/report.md, including the `fired` column -->
