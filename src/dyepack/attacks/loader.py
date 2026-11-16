from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from ..sandbox import ATTACKER_EMAIL, ATTACKER_URL

CHAINS_DIR = Path(__file__).parent / "chains"


@dataclass
class Attack:
    id: str
    channel: str      # tool_output | tool_poisoning
    surface: str      # email | web | file | tool_description
    effort: int       # 1 (trivial) .. 5 (hard for the attacker)
    target: str       # api_key | ssn
    payload: str = ""
    owasp: str = "LLM01"
    target_tool: str | None = None
    server: str | None = None      # which lab server the injection rides in on (multi-server labs)
    after: int = 0                 # delayed payload: skip the first N calls of target_tool
    parts: list | None = None      # split payload: one part planted per call of target_tool
    env: dict | None = None        # extra environment for the lab servers in this attack's trials

    @property
    def family(self) -> str:
        """Coarse attack family for coverage tables."""
        if self.surface == "native":
            return "native_poison"
        if self.surface == "page":
            return "page_injection"
        if self.parts:
            return "split_payload"
        if self.after:
            return "delayed_payload"
        if self.id.split("+")[0].startswith("chain_"):
            return "encoded_chain"
        if self.surface == "tool_description":
            return "description_poison"
        return "persuasion"

    def injection(self) -> dict | None:
        if self.surface == "native":      # the lab server is itself malicious; nothing to plant
            return {"surface": "native"}
        if self.surface == "page":        # the lab server renders the payload into its own pages
            return {"surface": "page", "payload": self.payload, "vector": (self.env or {}).get("PAGE_VECTOR")}
        spec = {"surface": self.surface, "payload": self.payload, "target_tool": self.target_tool}
        if self.server:
            spec["server"] = self.server
        if self.after:
            spec["after"] = self.after
        if self.parts:
            spec["parts"] = list(self.parts)
        return spec


def _fill(text, subs: dict):
    """Lab substitutions first (they may contain the attacker placeholders), then the attacker's."""
    if not isinstance(text, str):
        return text
    for k, v in (subs or {}).items():
        text = text.replace("{" + k + "}", v)
    return text.replace("{attacker_email}", ATTACKER_EMAIL).replace("{attacker_url}", ATTACKER_URL)


def load_attacks(path: str | Path | None = None, subs: dict | None = None) -> list[Attack]:
    """Load one YAML file, or every *.yaml in a directory (default: the bundled chains).
    `subs` fills {placeholders} in templates, e.g. {read_secret} for a given lab."""
    p = Path(path) if path else CHAINS_DIR
    files = sorted(p.glob("*.yaml")) if p.is_dir() else [p]
    out: list[Attack] = []
    for f in files:
        for d in yaml.safe_load(f.read_text()) or []:
            d["payload"] = d.get("payload") or ""
            for key in ("payload", "target_tool", "server"):
                d[key] = _fill(d.get(key), subs)
            if d.get("env"):
                d["env"] = {k: _fill(v, subs) for k, v in d["env"].items()}
            if d.get("parts"):
                d["parts"] = [_fill(x, subs) for x in d["parts"]]
            out.append(Attack(**d))
    ids = [a.id for a in out]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate attack ids: {sorted(dupes)}")
    return out
