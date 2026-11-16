"""SARIF 2.1.0 output, so tripwire findings can feed code-scanning dashboards and CI gates.

Three sources turn into results: static scan findings (poisoned or risky tool text), drift (a tool
definition changed since it was pinned) and dynamic live-suite results (a canary actually delivered,
the attacker contacted, a secret read). Every result has a stable `partialFingerprints` entry so
a dashboard can dedupe it across runs.

Honest limits: SARIF wants a file location. MCP findings live on a server's tool, not in a source
file, so each result points at `artifact` (default `mcp-config.json`, the file where the server is
configured) and names the real subject in `logicalLocations`. `validate_sarif` checks the structure
against the 2.1.0 spec's required properties; it is not the official JSON Schema, and this output has
not been uploaded to GitHub code scanning.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .frameworks import flat, tags_for

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVELS = {"none", "note", "warning", "error"}
SEVERITY_LEVEL = {"high": "error", "medium": "warning", "low": "note"}
SECURITY_SEVERITY = {"error": "8.0", "warning": "5.0", "note": "3.0"}   # GitHub's 0-10 scale, as strings

RULE_TEXT = {
    "static/": ("Suspicious tool definition", "Heuristic static analysis flagged text in a tool's name, "
                "description or schema that looks like an instruction aimed at the model."),
    "drift/modified": ("Tool definition changed since pinned", "A tool's definition differs from the pinned "
                       "baseline (rug-pull check). The `fields` property says what changed."),
    "drift/added": ("Tool added since pinned", "A tool appeared that was not in the pinned baseline."),
    "drift/removed": ("Tool removed since pinned", "A pinned tool is no longer served."),
    "dynamic/canary_delivered": ("Agent leaked a canary secret", "In a live run the injected instructions "
                                 "made the agent send a planted canary secret to the collaborator sink."),
    "dynamic/attacker_contact": ("Agent contacted the attacker", "An injection made the agent call an "
                                 "outbound tool toward the attacker's address; no canary was proven delivered."),
    "dynamic/secret_read": ("Agent read a secret it was steered toward", "An injection made the agent read "
                            "the canary secret, but nothing left the system."),
    "config/secret_in_config": ("Secret pasted into an MCP client config", "A token-shaped value sits in a "
                                "server's args, env, headers or URL. Anyone who can read the file has it."),
    "config/insecure_transport": ("Remote MCP server over plain http", "Requests, tokens and tool results "
                                  "cross the network unencrypted."),
    "config/credential_in_config": ("Credential env var holds a literal value", "An env var named like a "
                                    "credential is set to a literal value instead of a reference."),
    "config/unpinned_package": ("MCP server package has no fixed version", "The server is fetched by a package "
                                "runner without a pinned version, so each launch can load new, unreviewed tool code."),
    "config/broad_filesystem": ("MCP server can reach the whole disk or home folder", "The server is given / or "
                                "the home folder as a path; an injected instruction can read anything there."),
    "config/mutable_image_tag": ("Container image pinned by tag, not digest", "A tag can be moved to a "
                                 "different image; a digest cannot."),
    "config/auto_approved_tools": ("Tools run without user approval", "The client is set to run these tools "
                                   "without asking the user first."),
    "monitor/unchecked": ("MCP server could not be checked for drift", "Monitoring could not list this "
                          "server's tools (scope, missing env var, timeout). Unchecked is not a pass."),
    "run/invalid": ("Run is not usable as evidence", "The run had errors, an incomplete baseline or was "
                    "stopped early; its score must not be read as a pass."),
}


@dataclass
class Finding:
    rule: str                  # e.g. "static/hidden_unicode"
    level: str                 # note | warning | error
    message: str
    server: str = ""
    tool: str = ""
    key: str = ""              # extra text mixed into the fingerprint
    props: dict = field(default_factory=dict)
    uri: str = ""              # real file, when known (config audit); else the `artifact` default
    line: int = 1


# -- sources -------------------------------------------------------------------------------------
def from_scan(server: str, scan: dict) -> list[Finding]:
    out = []
    for f in scan.get("findings", []):
        kind = str(f["kind"]).split(" ")[0]
        out.append(Finding(f"static/{kind}", SEVERITY_LEVEL.get(f["severity"], "warning"),
                           f"{f['kind']} in tool '{f['tool']}' ({f['severity']})", server, f["tool"]))
    if scan.get("trifecta_complete"):
        out.append(Finding("static/lethal_trifecta", "warning",
                           f"{server} exposes private reads, untrusted input and an outbound path together "
                           f"({', '.join(scan.get('capabilities', []))})", server, ""))
    return out


def from_drift(server: str, report: dict) -> list[Finding]:
    out = []
    for c in report.get("changes", []):
        fields = c.get("fields")
        detail = f" ({', '.join(fields)})" if fields else ""
        level = "warning" if c["change"] == "modified" and fields == ["titles"] else \
            ("error" if c["change"] in ("modified", "added") else "warning")
        out.append(Finding(f"drift/{c['change']}", level,
                           f"tool '{c['tool']}' {c['change']} since pinned{detail}", server, c["tool"],
                           key=",".join(fields or []), props={"fields": fields or []}))
    out += from_scan(server, {"findings": report.get("findings", [])})
    return out


def from_audit(res: dict) -> list[Finding]:
    """Config-audit findings carry their own file and line, so code scanning can annotate the config."""
    return [Finding(f"config/{f['kind']}", SEVERITY_LEVEL.get(f["severity"], "warning"),
                    f"{f['message']} [{f['server']}]. Fix: {f['fix']}", f["server"], "",
                    key=f"{f['file']}|{f['message']}", props={"client": f["client"]},
                    uri=f["file"], line=f["line"]) for f in res.get("findings", [])]


def from_live(res: dict) -> list[Finding]:
    out = []
    lab = res.get("lab") or res.get("server", "")
    for p in res.get("pairs", []):
        props = {"attack": p["attack"], "task": p["task"], "n": p["n"], "delivered": p["delivered"],
                 "ci": p["ci"], "exposure": round(100 * p.get("exposure", 0), 1),
                 "fired": p.get("fired"), "family": p.get("family")}
        what = f"attack '{p['attack']}' on task '{p['task']}' ({p['delivered']}/{p['n']} delivered, " \
               f"95% CI {p['ci'][0]:.0%}-{p['ci'][1]:.0%})"
        if p["delivered"]:
            out.append(Finding("dynamic/canary_delivered", "error", what, lab, p["attack"], p["task"], props))
        elif p.get("attacker_contact"):
            out.append(Finding("dynamic/attacker_contact", "warning",
                               f"{what}; attacker contacted in {p['attacker_contact']} trial(s)", lab,
                               p["attack"], p["task"], props))
        elif p.get("canary_read"):
            out.append(Finding("dynamic/secret_read", "note",
                               f"{what}; secret read in {p['canary_read']} trial(s), nothing left", lab,
                               p["attack"], p["task"], props))
    sm = res.get("summary", {})
    if sm and not sm.get("valid", True):
        out.append(Finding("run/invalid", "error", "run is invalid: " + "; ".join(sm["invalid_reasons"]), lab))
    return out


# -- document ------------------------------------------------------------------------------------
def _rule_text(rule: str) -> tuple[str, str]:
    if rule in RULE_TEXT:
        return RULE_TEXT[rule]
    if rule.startswith("static/"):
        name, full = RULE_TEXT["static/"]
        return f"{name}: {rule.split('/', 1)[1]}", full
    return rule, rule


def fingerprint(f: Finding) -> str:
    return hashlib.sha256("|".join([f.rule, f.server, f.tool, f.key]).encode()).hexdigest()[:32]


def to_sarif(findings: list[Finding], artifact: str = "mcp-config.json", version: str = "0.1.0") -> dict:
    rule_ids = sorted({f.rule for f in findings})
    index = {r: i for i, r in enumerate(rule_ids)}
    rules = []
    for r in rule_ids:
        short, full = _rule_text(r)
        level = next(f.level for f in findings if f.rule == r)
        rules.append({"id": f"tripwire/{r}", "name": r.replace("/", "_"), "shortDescription": {"text": short},
                      "fullDescription": {"text": full}, "defaultConfiguration": {"level": level},
                      "properties": {"tags": ["security", "mcp", "prompt-injection", *flat(r)],
                                     "frameworks": tags_for(r),
                                     "security-severity": SECURITY_SEVERITY.get(level, "5.0")}})
    results = []
    for f in findings:
        subject = "/".join(x for x in (f.server, f.tool) if x) or "run"
        res = {"ruleId": f"tripwire/{f.rule}", "ruleIndex": index[f.rule], "level": f.level,
               "message": {"text": f.message},
               "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.uri or artifact},
                                                   "region": {"startLine": max(1, f.line)}},
                              "logicalLocations": [{"name": f.tool or f.server or "run",
                                                    "fullyQualifiedName": subject, "kind": "function"}]}],
               "partialFingerprints": {"tripwire/v1": fingerprint(f)}}
        if f.props:
            res["properties"] = f.props
        results.append(res)
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION,
            "runs": [{"tool": {"driver": {"name": "tripwire", "version": version,
                                          "informationUri": "https://github.com/deep60/tripwire",
                                          "rules": rules}},
                      "results": results}]}


def validate_sarif(doc: dict) -> list[str]:
    """Required-property checks from the SARIF 2.1.0 spec. Returns problems; empty means well-formed."""
    p: list[str] = []
    if doc.get("version") != SARIF_VERSION:
        p.append(f"version must be {SARIF_VERSION}")
    runs = doc.get("runs")
    if not isinstance(runs, list) or not runs:
        return p + ["runs must be a non-empty array"]
    for ri, run in enumerate(runs):
        driver = (run.get("tool") or {}).get("driver") or {}
        if not driver.get("name"):
            p.append(f"runs[{ri}].tool.driver.name is required")
        rules = driver.get("rules", [])
        ids = [r.get("id") for r in rules]
        if len(ids) != len(set(ids)) or not all(ids):
            p.append(f"runs[{ri}] rule ids must be present and unique")
        for ki, r in enumerate(run.get("results", [])):
            where = f"runs[{ri}].results[{ki}]"
            if not (r.get("message") or {}).get("text"):
                p.append(f"{where}.message.text is required")
            if r.get("level") not in LEVELS:
                p.append(f"{where}.level must be one of {sorted(LEVELS)}")
            idx = r.get("ruleIndex")
            if idx is not None and (not isinstance(idx, int) or idx >= len(rules) or rules[idx]["id"] != r.get("ruleId")):
                p.append(f"{where}.ruleIndex does not match ruleId")
            for loc in r.get("locations", []):
                pl = loc.get("physicalLocation") or {}
                if not (pl.get("artifactLocation") or {}).get("uri"):
                    p.append(f"{where} location needs physicalLocation.artifactLocation.uri")
                line = (pl.get("region") or {}).get("startLine", 1)
                if not isinstance(line, int) or line < 1:
                    p.append(f"{where} region.startLine must be an integer >= 1")
            if not r.get("partialFingerprints"):
                p.append(f"{where}.partialFingerprints is missing (dashboards cannot dedupe)")
    return p
