"""OCSF (Open Cybersecurity Schema Framework) output, so dyepack findings can be loaded by tools that
ingest OCSF (security data lakes, SIEM pipelines) without a custom parser.

Each finding becomes one *Detection Finding* event (class_uid 2004, category 2 "Findings"). The
file-integrity-style classes are not used: dyepack reports on MCP tools and agent behavior, not on
files. Frameworks (OWASP LLM, MITRE ATLAS, NIST 800-53) ride in `finding_info.types` and
`unmapped.frameworks`.

Honest limits: the required-field list in `validate_ocsf` was written from the OCSF 1.1.0 schema as I
know it; it is not the official validator, and no SIEM or data lake has ingested this output yet.
Transport is a file (JSON array, or NDJSON for `.ndjson`/`.jsonl` paths) or the signed webhook in
`notify.py`. There is no OTLP exporter.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from .frameworks import flat, tags_for
from .sarif import Finding, _rule_text, fingerprint

OCSF_VERSION = "1.1.0"
CLASS_UID, CATEGORY_UID = 2004, 2
ACTIVITY_CREATE = 1
TYPE_UID = CLASS_UID * 100 + ACTIVITY_CREATE            # 200401
SEVERITY_ID = {"error": 4, "warning": 3, "note": 2}       # 4 High, 3 Medium, 2 Low
SEVERITY_NAME = {1: "Informational", 2: "Low", 3: "Medium", 4: "High"}
REQUIRED = ("activity_id", "category_uid", "class_uid", "finding_info", "metadata", "severity_id",
            "time", "type_uid")


def to_ocsf(findings: list[Finding], version: str = "0.1.0", now_ms: int | None = None) -> list[dict]:
    now = int(time.time() * 1000) if now_ms is None else now_ms
    events = []
    for f in findings:
        sev = SEVERITY_ID.get(f.level, 3)
        title, desc = _rule_text(f.rule)
        subject = "/".join(x for x in (f.server, f.tool) if x) or "run"
        ev = {
            "activity_id": ACTIVITY_CREATE, "activity_name": "Create",
            "category_uid": CATEGORY_UID, "category_name": "Findings",
            "class_uid": CLASS_UID, "class_name": "Detection Finding",
            "type_uid": TYPE_UID, "type_name": "Detection Finding: Create",
            "severity_id": sev, "severity": SEVERITY_NAME[sev],
            "status_id": 1, "status": "New",
            "time": now,
            "message": f.message,
            "metadata": {"version": OCSF_VERSION,
                         "product": {"name": "dyepack", "vendor_name": "dyepack", "version": version}},
            "finding_info": {"uid": fingerprint(f), "title": title, "desc": desc,
                             "types": [f.rule, *flat(f.rule)]},
            "resources": [{"type": "MCP tool" if f.tool else "MCP server", "name": f.tool or f.server or "run",
                           "uid": subject}],
            "unmapped": {"rule": f.rule, "frameworks": tags_for(f.rule), **({"props": f.props} if f.props else {})},
        }
        events.append(ev)
    return events


def validate_ocsf(events: list[dict]) -> list[str]:
    p: list[str] = []
    for i, e in enumerate(events):
        for k in REQUIRED:
            if k not in e:
                p.append(f"event[{i}] missing required field '{k}'")
        if e.get("type_uid") != e.get("class_uid", 0) * 100 + e.get("activity_id", 0):
            p.append(f"event[{i}] type_uid must equal class_uid*100+activity_id")
        fi = e.get("finding_info") or {}
        if not fi.get("title") or not fi.get("uid"):
            p.append(f"event[{i}] finding_info needs title and uid")
        prod = ((e.get("metadata") or {}).get("product") or {})
        if not (e.get("metadata") or {}).get("version") or not prod.get("name"):
            p.append(f"event[{i}] metadata needs version and product.name")
        if e.get("severity_id") not in (0, 1, 2, 3, 4, 5, 6, 99):
            p.append(f"event[{i}] severity_id out of range")
        if not isinstance(e.get("time"), int):
            p.append(f"event[{i}] time must be integer epoch milliseconds")
    return p


def write_ocsf(events: list[dict], path: str) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.suffix in (".ndjson", ".jsonl"):
        out.write_text("".join(json.dumps(e) + "\n" for e in events))
    else:
        out.write_text(json.dumps(events, indent=2))
