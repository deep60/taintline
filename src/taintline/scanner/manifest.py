from __future__ import annotations

from . import static_poison, toxic_flow


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
    return {"findings": findings, **toxic_flow.analyze(tools)}
