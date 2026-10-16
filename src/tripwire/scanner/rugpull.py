"""Rug-pull detection: pin tool hashes now, diff against a later listing."""
from __future__ import annotations

from ..gateway.hash import hash_tools


def pin(tools: list[dict]) -> dict[str, str]:
    return hash_tools(tools)


def diff_pins(pins: dict[str, str], tools: list[dict]) -> list[dict]:
    new = hash_tools(tools)
    changes = []
    for name, h in pins.items():
        if name not in new:
            changes.append({"tool": name, "change": "removed"})
        elif new[name] != h:
            changes.append({"tool": name, "change": "modified"})
    changes += [{"tool": n, "change": "added"} for n in new if n not in pins]
    return changes
