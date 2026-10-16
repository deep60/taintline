"""Tool inventory. Offline (from a saved manifest) works now; live enumeration needs the
Phase 1 MCP client."""
from __future__ import annotations

import json
from pathlib import Path

from ..gateway.hash import hash_tool


def load_tools(path: str | Path) -> list[dict]:
    data = json.loads(Path(path).read_text())
    return data["tools"] if isinstance(data, dict) else data


def inventory(tools: list[dict]) -> list[dict]:
    return [{"name": t.get("name"), "description": t.get("description", ""),
             "hash": hash_tool(t)} for t in tools]


def enumerate_server(*args, **kwargs):
    raise NotImplementedError("Phase 1: live enumeration needs the MCP client")
