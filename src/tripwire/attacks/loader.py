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
    payload: str
    owasp: str = "LLM01"
    target_tool: str | None = None

    def injection(self) -> dict:
        return {"surface": self.surface, "payload": self.payload,
                "target_tool": self.target_tool}


def load_attacks(path: str | Path | None = None) -> list[Attack]:
    """Load one YAML file, or every *.yaml in a directory (default: the bundled chains)."""
    p = Path(path) if path else CHAINS_DIR
    files = sorted(p.glob("*.yaml")) if p.is_dir() else [p]
    out: list[Attack] = []
    for f in files:
        for d in yaml.safe_load(f.read_text()) or []:
            d["payload"] = (d["payload"].replace("{attacker_email}", ATTACKER_EMAIL)
                                        .replace("{attacker_url}", ATTACKER_URL))
            out.append(Attack(**d))
    ids = [a.id for a in out]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate attack ids: {sorted(dupes)}")
    return out
