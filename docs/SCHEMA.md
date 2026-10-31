# Result file schema

Every `results.json` carries `schema_version` (currently `1.0`) and `kind` (`run`, `live_suite`, `live_run`).

- Same major version: readers keep working; new minor versions only add fields.
- No `schema_version`: written before versioning; still readable (treated as 0.x).
- Higher major version than the installed tripwire: refused with an "upgrade tripwire" message.

## History
- **1.0** (2026-10-31): first versioned format. `live_suite` adds `summary.valid` / `summary.invalid_reasons`,
  `budget` (trials, tokens, seconds, limits, `stopped_by`), per-pair `family`, `surface`, `planned`, `fired`
  and per-trial `tokens`, `injection_fired`, `max_turns`.

Migration: nothing to do for old files. To bring an old `live_suite` file up to 1.0, rerun it; the missing
fields (`fired`, `family`, `budget`) cannot be reconstructed from old data.
