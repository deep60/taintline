"""Run limits for paid or slow targets. Trials are checked before the run starts; time and tokens
are checked between trials, so a run can overshoot by at most one trial. A run stopped by its budget
is marked incomplete and is never reported as a clean pass."""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class Budget:
    max_trials: int | None = None
    max_seconds: float | None = None
    max_tokens: int | None = None
    trials: int = 0
    tokens: int = 0
    _t0: float = field(default_factory=time.monotonic)

    def preflight(self, planned_trials: int) -> str | None:
        if self.max_trials is not None and planned_trials > self.max_trials:
            return f"plan needs {planned_trials} trials, over --max-trials {self.max_trials}"
        return None

    @property
    def seconds(self) -> float:
        return time.monotonic() - self._t0

    def add(self, tokens: int = 0) -> None:
        self.trials += 1
        self.tokens += tokens or 0

    def exhausted(self) -> str | None:
        if self.max_seconds is not None and self.seconds >= self.max_seconds:
            return f"time budget {self.max_seconds:.0f}s used"
        if self.max_tokens is not None and self.tokens >= self.max_tokens:
            return f"token budget {self.max_tokens} used"
        return None

    def report(self) -> dict:
        return {"trials": self.trials, "tokens": self.tokens, "seconds": round(self.seconds, 1),
                "limits": {"max_trials": self.max_trials, "max_seconds": self.max_seconds,
                           "max_tokens": self.max_tokens}}
