"""Lethal-trifecta analysis: private data + untrusted input + a way out."""
from __future__ import annotations

import re

CAP_HINTS = {
    "private_read": r"read|file|database|query|secret|credential|drive|email|inbox|note",
    "untrusted_in": r"fetch|browse|web|scrape|search|url|inbox|email|download",
    "external_out": r"send|post|upload|webhook|publish|http|forward|write.*remote",
}
TRIFECTA = {"private_read", "untrusted_in", "external_out"}


def capabilities(tool: dict) -> set[str]:
    blob = f"{tool.get('name', '')} {tool.get('description', '')}".lower()
    return {cap for cap, pat in CAP_HINTS.items() if re.search(pat, blob)}


def analyze(tools: list[dict]) -> dict:
    caps: set[str] = set()
    for t in tools:
        caps |= capabilities(t)
    return {"capabilities": sorted(caps), "trifecta_complete": TRIFECTA <= caps}
