# Attack of the month: <name>

*Copy this file to `YYYY-MM-<attack-id>.md`. Keep it under 600 words, with one table or chart.
Every number comes from a run folder you can name.*

**One line:** what the attack does, and the result in one number with its interval and sample size.

## The attack
- **Contributed by:** @handle (link the PR)
- **Lab / surface:** e.g. `inbox`, payload in a tool result
- **The idea:** what disguise, hiding place or trick it uses, and why it might work

```yaml
# the attack entry, exactly as merged
```

## What happened
| model | prompt | fired | delivered (95% CI) | attacker contacted | errors |
|---|---|---|---|---|---|

- Check `fired` first. If the payload never reached the model, the leak rate means nothing.
- Errored trials are listed, never counted as resisted.
- One trace worth showing: link or screenshot the run's `replay.html`.

## Why it matters
Which real deployments look like this lab, and what a defender should do.

## Reproduce
```bash
taintline live-suite --lab <lab> --attacks <file> -n <n> --agent ... --model ... --out out/<run>
```
