from __future__ import annotations

from . import static_poison, toxic_flow
from .prove import proof_for


def scan_manifest(manifest) -> dict:
    tools = manifest["tools"] if isinstance(manifest, dict) else manifest
    findings, names = [], {}
    for t in tools:
        findings += static_poison.scan_tool(t)
        names[t.get("name")] = names.get(t.get("name"), 0) + 1
    for n, c in names.items():
        if c > 1:
            findings.append({"tool": n, "kind": "duplicate_tool_name (shadowing risk)",
                             "severity": "high"})
    for f in findings:
        f["prove"] = proof_for(f["kind"])
    flow = toxic_flow.analyze(tools)
    if flow["trifecta_complete"]:
        flow["prove"] = proof_for("lethal_trifecta")
    return {"findings": findings, **flow}
