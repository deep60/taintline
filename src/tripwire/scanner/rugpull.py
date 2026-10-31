"""Rug-pull detection: pin tool hashes now, diff against a later listing."""
from __future__ import annotations

from ..gateway.hash import detail_tool, hash_tools


def pin(tools: list[dict]) -> dict[str, dict]:
    """name -> {hash, description, schema, titles}. Older pin files (name -> hash string) still work."""
    out = {}
    for name, h in hash_tools(tools).items():
        t = next(x for x in tools if x.get("name", "") == name.split("#")[0])
        out[name] = detail_tool(t) if "#" not in name else {"hash": h}
    return out


def check(pins: dict[str, str], tools: list[dict]) -> dict:
    """Drift report: what changed since approval, plus static-scan findings on the changed tools."""
    from .static_poison import scan_tool

    changes = diff_pins(pins, tools)
    touched = {c["tool"].split("#")[0] for c in changes if c["change"] != "removed"}
    findings = [f for t in tools if t.get("name") in touched for f in scan_tool(t)]
    return {"changes": changes, "findings": findings}


def diff_pins(pins: dict, tools: list[dict]) -> list[dict]:
    """Changes since the pins. A modified tool lists WHICH parts changed when the pin has detail:
    `description`, `schema` (parameters, types, defaults) or `titles` (schema title annotations only)."""
    new = hash_tools(tools)
    by_name = {}
    for t in tools:
        by_name.setdefault(t.get("name", ""), t)
    changes = []
    for name, old in pins.items():
        old_hash = old["hash"] if isinstance(old, dict) else old
        if name not in new:
            changes.append({"tool": name, "change": "removed"})
        elif new[name] != old_hash:
            c = {"tool": name, "change": "modified"}
            if isinstance(old, dict) and "description" in old and "#" not in name:
                now = detail_tool(by_name[name])
                c["fields"] = [f for f in ("description", "schema", "titles") if now[f] != old[f]
                               and not (f == "titles" and now["schema"] != old["schema"])]
            changes.append(c)
    changes += [{"tool": n, "change": "added"} for n in new if n not in pins]
    return changes
