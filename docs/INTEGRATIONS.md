# Integrations: OCSF export, signed webhooks, framework tags

Local CLI features, in the same family as SARIF output. They need no server and no account.

## Framework tags
Every finding rule maps to OWASP Top 10 for LLM Applications (2025), MITRE ATLAS and NIST SP 800-53 Rev. 5
identifiers (`src/dyepack/report/frameworks.py`). They appear as SARIF rule tags, in OCSF
`finding_info.types`, in webhook payloads and in a "Framework mapping" table in the live-suite report.

| finding | OWASP LLM | ATLAS | NIST 800-53 |
|---|---|---|---|
| canary delivered to the sink | LLM01, LLM02, LLM06 | AML.T0051.001, AML.T0057 | SI-10, AC-4 |
| attacker contacted | LLM01, LLM06 | AML.T0051.001 | SI-10, AC-4 |
| secret read, nothing left | LLM01, LLM02 | AML.T0051.001 | SI-10 |
| tool definition drift (rug pull) | LLM03 | AML.T0010 | SI-7, SR-3 |
| suspicious tool text | LLM01, LLM03 | AML.T0051.001 | SI-10 |
| lethal trifecta present | LLM06 | none | AC-4 |

These are mapping aids, not compliance results. The identifiers were written from memory; re-check ATLAS
in particular against the current catalog before quoting them in an audit. PCI-DSS, HIPAA and SOC 2 are
deliberately not mapped: they govern host file-integrity monitoring, which dyepack does not do.

## OCSF export
```bash
uv run dyepack monitor --server notes --command python --arg lab/servers/notes_server.py --ocsf out/drift.ndjson
uv run dyepack live-suite --lab notes ... --ocsf out/findings.json
uv run dyepack ocsf --live out/live_suite/results.json --out out/findings.ndjson   # from saved results
```
Each finding is one OCSF 1.1.0 **Detection Finding** (class 2004, category Findings). `.ndjson`/`.jsonl`
paths write one event per line, anything else a JSON array. `finding_info.uid` is stable across runs, so a
receiver can dedupe.

Limits: the schema check is ours, not the official OCSF validator, and no SIEM or data lake has ingested the
output yet. There is no OTLP exporter; deliver files with your own shipper or use the webhook.

## Signed webhooks
```bash
export DYEPACK_WEBHOOK_SECRET=...        # signing secret; never pass it on the command line
uv run dyepack monitor --server notes --command python --arg lab/servers/notes_server.py \
  --notify-url https://hooks.example.com/dyepack
```
Add the receiver's `host[:port]` to `SCOPE.yaml` `servers` first; an unlisted destination is refused. Events:
`drift`, `leak` (a canary reached the sink) and `invalid_run`. Nothing is sent when there is nothing to
report. `--notify-dry-run` builds and signs without sending.

Each request has `X-Dyepack-Timestamp`, `X-Dyepack-Event` and
`X-Dyepack-Signature: sha256=<hex>`, an HMAC-SHA256 of `"<timestamp>.<raw body>"`. Receivers verify with
`dyepack.notify.verify(body, headers, secret)` (rejects a bad signature or a timestamp older than 5 minutes).

Behavior: https only (plain http is allowed for localhost), redirects are not followed, 5xx and network errors
are retried twice, 4xx is not. A delivery failure prints a warning and never changes the command's exit code
(a drift run still exits 1).

What it does not do: isolate hosts, revoke cloud credentials or format for a specific tool. Point it at your own
receiver or an automation platform's generic webhook trigger.

## Not built, on purpose
Endpoint agents and SPIFFE enrollment, fleet policy push, multi-tenant RBAC/SSO/SCIM and a hosted console. They
describe a host-monitoring product, or need the hosted service that `docs/PLAN.md` says to build only after
design partners are using the CLI.
