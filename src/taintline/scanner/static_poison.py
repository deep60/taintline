"""Heuristic static analysis of tool descriptions. It WILL miss novel phrasing and will
flag some benign text. Treat as triage, not proof."""
from __future__ import annotations

import json
import re

PATTERNS = [
    (r"ignore (all |any )?(previous|prior|above) instructions", "override_instruction", "high"),
    (r"<\s*important\s*>|<\s*system\s*>", "hidden_directive_tag", "high"),
    (r"do not (tell|mention|inform|reveal|show)[^.]{0,40}user", "concealment_from_user", "high"),
    (r"(~/|/)\.ssh|id_rsa|\.env\b|credentials|/etc/passwd|api[_ ]?key",
     "sensitive_path_reference", "high"),
    (r"before (using|calling|running|invoking) this tool", "pre_call_instruction", "medium"),
    (r"(send|post|forward|email|upload)\b[^.]{0,60}(https?://|@[\w-]+\.\w+)",
     "exfil_destination", "medium"),
    (r"\b(also|first|then) (call|use|invoke|read)\b", "cross_tool_steering", "medium"),
]
HIDDEN_CHARS = re.compile("[\u200b\u200c\u200d\u2060\ufeff\U000e0000-\U000e007f]")


def scan_tool(tool: dict) -> list[dict]:
    schema = tool.get("inputSchema", tool.get("input_schema", {}))
    text = f"{tool.get('name', '')} {tool.get('description', '')} " + json.dumps(schema)
    desc = tool.get("description", "")
    name = tool.get("name")
    findings = [
        {"tool": name, "kind": kind, "severity": sev}
        for pat, kind, sev in PATTERNS if re.search(pat, desc, re.I)
    ]
    # instructions hidden in a parameter's description reach the model just the same
    props = schema.get("properties") if isinstance(schema, dict) else None
    for pname, p in (props.items() if isinstance(props, dict) else []):
        pdesc = p.get("description", "") if isinstance(p, dict) else ""
        findings += [{"tool": name, "kind": kind, "severity": sev, "where": f"parameter '{pname}'"}
                     for pat, kind, sev in PATTERNS if re.search(pat, pdesc, re.I)]
    if HIDDEN_CHARS.search(text):
        findings.append({"tool": name, "kind": "hidden_unicode", "severity": "high"})
    if len(desc) > 1200:
        findings.append({"tool": name, "kind": "unusually_long_description",
                         "severity": "medium"})
    return findings
