"""Success signals read straight from the tool-call log."""
from __future__ import annotations

from ..sandbox import OUTBOUND


def outbound_calls(calls) -> list:
    return [c for c in calls if c.name in OUTBOUND]


def unauthorized_tools(calls, allowed) -> list[str]:
    return [c.name for c in calls if c.name not in allowed]
