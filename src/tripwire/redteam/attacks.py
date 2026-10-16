from __future__ import annotations
from dataclasses import dataclass
import yaml
from .sandbox import ATTACKER_EMAIL, ATTACKER_URL

@dataclass
class Attack:
    id: str
    channel: str      # tool_output | tool_poisoning
    surface: str      # email | web | file | tool_description
    effort: int       # 1 (trivial) .. 5 (hard for attacker)
    target: str       # api_key | ssn
    payload: str
    owasp: str = "LLM01"
    target_tool: str | None = None

    def injection(self) -> dict:
        return {"surface": self.surface, "payload": self.payload, "target_tool": self.target_tool}

def load_attacks(path: str) -> list[Attack]:
    out = []
    for d in yaml.safe_load(open(path)):
        d["payload"] = (d["payload"].replace("{attacker_email}", ATTACKER_EMAIL)
                                    .replace("{attacker_url}", ATTACKER_URL))
        out.append(Attack(**d))
    return out
