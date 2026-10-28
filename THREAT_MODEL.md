# Threat model

Tripwire is an offensive-testing tool: it deliberately plants prompt injection and tool
poisoning against AI agents. This document says what it protects, who it defends against,
and where it must not be used.

## Purpose
Measure whether an agent (and the MCP tools it connects to) can be manipulated into leaking
secrets or acting for an attacker, with reproducible, deterministic evidence.

## Assets
- **Target systems** the user is authorized to test (agents, model endpoints, MCP servers).
- **Real credentials and data** on or near those targets. Tripwire must never need them;
  all secrets in a run are synthetic canaries (`sk-live-CANARY…`, `CANARY-SSN-…`).
- **Run evidence** (`results.json`, traces, reports): may contain model output and attack
  payloads; treat as sensitive.
- **Tripwire's own integrity**: the attack library hash and run metadata that make results
  attributable.

## Adversaries and misuse cases
| Who | Goal | Mitigation |
|---|---|---|
| Careless operator | Points the tool at a system they do not own or may not test | Default-deny scope gate: `run` refuses any network target not listed in `SCOPE.yaml`; no wildcards; `authorized_by` required |
| Malicious operator | Uses the attack library against third parties | Out of scope for the tool; license is "as is", docs state authorized use only. The gate raises the bar but cannot stop a determined user who edits the scope file |
| Hostile target | Returns content that tries to steer Tripwire itself | No LLM judging; oracles are deterministic string/destination checks; target output is data only |
| Poisoned attack file | Third-party attack YAML that exfiltrates real data | Attacks run against a sandbox of fake tools with canary data only; library hashed into run metadata |
| Report reader | Is misled by a false result | Errors never count as "secure"; baseline false-alarm rate and CIs reported; unrequested outbound calls reported separately from attack success |

## Trust boundaries
1. Operator ↔ Tripwire CLI: the operator is trusted but their authorization is recorded.
2. Tripwire ↔ target (model API, Ollama, MCP server): untrusted network boundary; every
   connection is checked by `scope.Gate` before the run starts.
3. Tripwire ↔ sandbox: in-process fake tools; nothing real is reachable from them.
4. Planned: collaborator sink (`lab/`), an isolated host that receives exfiltration
   attempts. Must have no route to the internet.

## Authorization model
- `SCOPE.yaml` (git-ignored) lists servers (host:port or stdio name), optional tool
  allow-list, and `fuzz` (active probing). Anything not listed is refused.
- In-process mock agents never touch the network and need no scope.
- Hosted model APIs (e.g. `api.anthropic.com`) must also be listed: the operator confirms
  they are permitted to send attack content to that provider under its terms.
- `--dry-run` validates scope and prints the plan with no calls.

## Out of scope
- Testing systems without written permission.
- Denial of service, load testing, credential guessing, or exploitation of vulnerabilities
  in target infrastructure.
- Defending a deployed agent at runtime (Tripwire is not a guardrail).
- Guarantees of coverage: a clean result means "these attacks did not succeed", not "safe".

## Data handling
- Only synthetic canaries are used; do not put real secrets in lab data.
- Traces are written to the `--out` directory in plaintext. Do not commit runs that used
  proprietary prompts or non-public targets.
- Telemetry: none.

## Known limitations
- Encoded exfiltration (base64, split, URL-encoded secrets) is not recognized as a leak;
  it appears only as an unrequested outbound call.
- Real MCP connectivity (client, proxy, live enumeration) is not implemented yet, so the
  gate currently covers the model-API targets only. It must be called from every new
  connection path as those are added.
- The scope file is a safeguard against mistakes, not against deliberate misuse.

## Disclosure
Report vulnerabilities in Tripwire privately to the maintainer (see repository contact).
If a run finds a vulnerability in a third-party product, follow that vendor's disclosure
policy and the terms of your authorization.
