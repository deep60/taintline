"""Map taintline finding rules to external risk frameworks, so a finding can be filed under the
control a reviewer already tracks.

These are MAPPING AIDS, not compliance claims: a finding tagged `NIST-800-53:SI-7` means "this is the
kind of issue that control is about", not "your system passes or fails that control". Identifiers
were written from memory of the published catalogs (OWASP Top 10 for LLM Applications 2025, MITRE
ATLAS, NIST SP 800-53 Rev. 5). ATLAS in particular renumbers: re-check them against the current
catalog before putting them in an audit document.

Deliberately absent: PCI-DSS, HIPAA and SOC 2. Those control file-integrity monitoring on hosts, and
taintline does not watch hosts.
"""
from __future__ import annotations

OWASP = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM06": "Excessive Agency",
}
ATLAS = {
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0010": "ML Supply Chain Compromise",
}
NIST = {
    "SI-7": "Software, Firmware, and Information Integrity",
    "SI-10": "Information Input Validation",
    "AC-4": "Information Flow Enforcement",
    "SR-3": "Supply Chain Controls and Processes",
}
CATALOGS = {"owasp_llm": OWASP, "mitre_atlas": ATLAS, "nist_800_53": NIST}

_INJECTION = {"owasp_llm": ["LLM01"], "mitre_atlas": ["AML.T0051.001"], "nist_800_53": ["SI-10"]}
_DRIFT = {"owasp_llm": ["LLM03"], "mitre_atlas": ["AML.T0010"], "nist_800_53": ["SI-7", "SR-3"]}

# exact rule first, then longest matching prefix
RULE_TAGS = {
    "static/lethal_trifecta": {"owasp_llm": ["LLM06"], "mitre_atlas": [], "nist_800_53": ["AC-4"]},
    "drift/modified": _DRIFT,
    "drift/added": _DRIFT,
    "drift/removed": _DRIFT,
    "dynamic/canary_delivered": {"owasp_llm": ["LLM01", "LLM02", "LLM06"],
                                 "mitre_atlas": ["AML.T0051.001", "AML.T0057"],
                                 "nist_800_53": ["SI-10", "AC-4"]},
    "dynamic/attacker_contact": {"owasp_llm": ["LLM01", "LLM06"], "mitre_atlas": ["AML.T0051.001"],
                                 "nist_800_53": ["SI-10", "AC-4"]},
    "dynamic/secret_read": {"owasp_llm": ["LLM01", "LLM02"], "mitre_atlas": ["AML.T0051.001"],
                            "nist_800_53": ["SI-10"]},
    "run/invalid": {"owasp_llm": [], "mitre_atlas": [], "nist_800_53": []},
}
PREFIX_TAGS = {"static/": {"owasp_llm": ["LLM01", "LLM03"], "mitre_atlas": ["AML.T0051.001"],
                           "nist_800_53": ["SI-10"]}}


def tags_for(rule: str) -> dict[str, list[str]]:
    if rule in RULE_TAGS:
        return {k: list(v) for k, v in RULE_TAGS[rule].items()}
    for prefix in sorted(PREFIX_TAGS, key=len, reverse=True):
        if rule.startswith(prefix):
            return {k: list(v) for k, v in PREFIX_TAGS[prefix].items()}
    return {k: [] for k in CATALOGS}


def flat(rule: str) -> list[str]:
    """['OWASP-LLM:LLM01', 'MITRE-ATLAS:AML.T0051.001', 'NIST-800-53:SI-10', ...] for tag lists."""
    label = {"owasp_llm": "OWASP-LLM", "mitre_atlas": "MITRE-ATLAS", "nist_800_53": "NIST-800-53"}
    t = tags_for(rule)
    return [f"{label[c]}:{i}" for c in CATALOGS for i in t[c]]


def coverage(findings) -> dict[str, dict[str, int]]:
    """For a report: how many findings fall under each framework control."""
    out: dict[str, dict[str, int]] = {c: {} for c in CATALOGS}
    for f in findings:
        for cat, ids in tags_for(f.rule).items():
            for i in ids:
                out[cat][i] = out[cat].get(i, 0) + 1
    return out
