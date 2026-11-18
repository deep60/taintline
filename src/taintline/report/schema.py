"""Versioned result files. Every results.json written by taintline carries `schema_version` and `kind`
so a CI job or a later taintline can tell what it is reading.

Compatibility rule: a reader accepts the same MAJOR version (new minor versions only add fields) and
files with no version at all (written before versioning, treated as 0.x). A higher MAJOR version is
refused with a clear message instead of being misread. See docs/SCHEMA.md for the field history.
"""
from __future__ import annotations

import json
from pathlib import Path

SCHEMA_VERSION = "1.0"
KINDS = {"run", "live_suite", "live_run"}


class SchemaError(ValueError):
    pass


def stamp(data: dict, kind: str) -> dict:
    if kind not in KINDS:
        raise ValueError(f"unknown result kind {kind!r}")
    return {"schema_version": SCHEMA_VERSION, "kind": kind, **{k: v for k, v in data.items()
                                                                 if k not in ("schema_version", "kind")}}


def check_version(data: dict, where: str = "results file") -> str:
    v = str(data.get("schema_version", "0.0"))
    try:
        major = int(v.split(".")[0])
    except ValueError:
        raise SchemaError(f"{where}: unreadable schema_version {v!r}") from None
    if major > int(SCHEMA_VERSION.split(".")[0]):
        raise SchemaError(f"{where} has schema_version {v}, newer than this taintline understands "
                          f"({SCHEMA_VERSION}). Upgrade taintline.")
    return v


def load_results(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text())
    check_version(data, str(path))
    return data
