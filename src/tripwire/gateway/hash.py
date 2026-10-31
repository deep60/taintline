"""Tool-definition hashing, for rug-pull detection (a tool changing after approval)."""
from __future__ import annotations

import hashlib
import json


def canonical(tool: dict) -> str:
    schema = tool.get("inputSchema", tool.get("input_schema", {}))
    return json.dumps(
        {"name": tool.get("name", ""), "description": tool.get("description", ""),
         "schema": schema},
        sort_keys=True, ensure_ascii=True, separators=(",", ":"),
    )


def hash_tool(tool: dict) -> str:
    return hashlib.sha256(canonical(tool).encode()).hexdigest()


def hash_tools(tools: list[dict]) -> dict[str, str]:
    """name -> hash. Duplicate names get '#2', '#3' suffixes (and are a shadowing smell)."""
    out: dict[str, str] = {}
    for t in tools:
        name, i = t.get("name", ""), 1
        key = name
        while key in out:
            i += 1
            key = f"{name}#{i}"
        out[key] = hash_tool(t)
    return out


def _strip_titles(node, in_properties: bool = False):
    """Drop schema `title` annotations (generator-assigned names), keeping real properties named title."""
    if isinstance(node, dict):
        return {k: _strip_titles(v, k == "properties") for k, v in node.items()
                if not (k == "title" and isinstance(v, str) and not in_properties)}
    if isinstance(node, list):
        return [_strip_titles(v) for v in node]
    return node


def _sha(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()


def detail_tool(tool: dict) -> dict:
    """Whole-definition hash plus per-part hashes, so a drift report can say WHAT changed."""
    schema = tool.get("inputSchema", tool.get("input_schema", {}))
    return {"hash": hash_tool(tool), "description": _sha(tool.get("description", "")),
            "schema": _sha(_strip_titles(schema)), "titles": _sha(schema)}
