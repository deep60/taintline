from __future__ import annotations

from pathlib import Path

import yaml

from .model import Scope

ALLOWED_KEYS = {"name", "authorized_by", "servers", "tools", "fuzz"}


class ScopeError(ValueError):
    pass


def parse_scope(d: dict) -> Scope:
    if not isinstance(d, dict):
        raise ScopeError("scope file must be a YAML mapping")
    unknown = set(d) - ALLOWED_KEYS
    if unknown:
        raise ScopeError(f"unknown keys: {sorted(unknown)}")
    for key in ("name", "authorized_by"):
        if not isinstance(d.get(key), str) or not d[key].strip():
            raise ScopeError(f"'{key}' is required and must be a non-empty string")
    servers = d.get("servers")
    if not isinstance(servers, list) or not servers or not all(isinstance(s, str) for s in servers):
        raise ScopeError("'servers' must be a non-empty list of strings")
    tools = d.get("tools")
    if tools is not None and (not isinstance(tools, list) or not all(isinstance(t, str) for t in tools)):
        raise ScopeError("'tools' must be a list of strings")
    fuzz = d.get("fuzz", False)
    if not isinstance(fuzz, bool):
        raise ScopeError("'fuzz' must be true or false")
    for entry in [*servers, *(tools or [])]:
        if "*" in entry:
            raise ScopeError("wildcards are not allowed: list targets explicitly")
    return Scope(d["name"].strip(), d["authorized_by"].strip(), tuple(servers),
                 tuple(tools) if tools is not None else None, fuzz)


def load_scope(path: str | Path) -> Scope:
    return parse_scope(yaml.safe_load(Path(path).read_text()))
