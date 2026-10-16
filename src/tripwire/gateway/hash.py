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
