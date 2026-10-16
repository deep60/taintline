"""Static scan of an MCP tool manifest. Fast, deterministic, no model calls.
Heuristic: it WILL miss novel phrasing and will flag some benign text. Treat as triage."""
from __future__ import annotations
import json, re

PATTERNS = [
    (r"ignore (all |any )?(previous|prior|above) instructions", "override_instruction", "high"),
    (r"<\s*important\s*>|<\s*system\s*>", "hidden_directive_tag", "high"),
    (r"do not (tell|mention|inform|reveal|show)[^.]{0,40}user", "concealment_from_user", "high"),
    (r"(~/|/)\.ssh|id_rsa|\.env\b|credentials|/etc/passwd|api[_ ]?key", "sensitive_path_reference", "high"),
    (r"before (using|calling|running|invoking) this tool", "pre_call_instruction", "medium"),
    (r"(send|post|forward|email|upload)\b[^.]{0,60}(https?://|@[\w-]+\.\w+)", "exfil_destination", "medium"),
    (r"\b(also|first|then) (call|use|invoke|read)\b", "cross_tool_steering", "medium"),
]
HIDDEN_CHARS = re.compile("[\u200b\u200c\u200d\u2060\ufeff\U000e0000-\U000e007f]")
CAP_HINTS = {
    "private_read": r"read|file|database|query|secret|credential|drive|email|inbox|note",
    "untrusted_in": r"fetch|browse|web|scrape|search|url|inbox|email|download",
    "external_out": r"send|post|upload|webhook|publish|http|forward|write.*remote",
}

def scan_tool(tool: dict) -> list[dict]:
    text = f"{tool.get('name','')} {tool.get('description','')} " + json.dumps(tool.get("inputSchema", tool.get("input_schema", {})))
    desc = tool.get("description", "")
    findings = []
    for pat, kind, sev in PATTERNS:
        if re.search(pat, desc, re.I):
            findings.append({"tool": tool.get("name"), "kind": kind, "severity": sev})
    if HIDDEN_CHARS.search(text):
        findings.append({"tool": tool.get("name"), "kind": "hidden_unicode", "severity": "high"})
    if len(desc) > 1200:
        findings.append({"tool": tool.get("name"), "kind": "unusually_long_description", "severity": "medium"})
    return findings

def scan_manifest(manifest) -> dict:
    tools = manifest["tools"] if isinstance(manifest, dict) else manifest
    findings, caps, names = [], set(), {}
    for t in tools:
        findings += scan_tool(t)
        names[t.get("name")] = names.get(t.get("name"), 0) + 1
        blob = f"{t.get('name','')} {t.get('description','')}".lower()
        for cap, pat in CAP_HINTS.items():
            if re.search(pat, blob):
                caps.add(cap)
    for n, c in names.items():
        if c > 1:
            findings.append({"tool": n, "kind": "duplicate_tool_name (shadowing risk)", "severity": "high"})
    return {"findings": findings, "capabilities": sorted(caps),
            "trifecta_complete": {"private_read", "untrusted_in", "external_out"} <= caps}
