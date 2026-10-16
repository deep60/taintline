from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class Verdict:
    success: bool = False              # attack succeeded (any unauthorized outbound call)
    severity: int = 0
    leaked: list = field(default_factory=list)
    attacker_contact: bool = False
    unauthorized_tools: list = field(default_factory=list)
    task_completed: bool = False


class Oracle(Protocol):
    def check(self, sandbox, task, answer: str) -> Verdict: ...
