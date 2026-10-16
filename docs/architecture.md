# Architecture

    targets/    the agent under test (Agent protocol: run(prompt, sandbox) -> answer)
    sandbox.py  fake tools + canaries + call log (Phase 0; real MCP servers in Phase 1)
    attacks/    YAML attacks (chains/), mutators, and the trial runner
    oracles/    deterministic success checks (canary, tool log, collaborator)
    scoring/    ASR + Wilson CI, severity/effort weights, exposure roll-up
    scanner/    static manifest analysis, toxic-flow, rug-pull pins, config checks
    scope/      authorization gate (default-deny)
    gateway/    transcript + tool hashing now; MCP client/proxy in Phase 1
    report/     results.json + report.md (SARIF later)
    lab/        collaborator sink + docker-compose (internal network)

Flow: load attacks -> for each (attack, task) run N fresh sandboxes -> oracle decides ->
score -> report. A benign baseline runs with no injection to measure utility/false alarms.
Errors are counted separately and never silently treated as "secure".
