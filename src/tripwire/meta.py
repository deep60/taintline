"""Run metadata. Results from different pins (model, library, version) must not be compared."""
from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from datetime import datetime, timezone

from . import __version__


def git_sha() -> str | None:
    try:
        out = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"],
                                      stderr=subprocess.DEVNULL, text=True, timeout=5)
        return out.strip() or None
    except Exception:
        return None


def attack_library_hash(attacks) -> str:
    """Stable under reordering; changes if any attack id, payload, surface or effort changes."""
    blob = json.dumps(sorted((a.id, a.payload, a.surface, a.effort) for a in attacks))
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def collect(*, agent: str, model: str | None, system_override: bool, n: int, attacks,
            mutators: list[str]) -> dict:
    return {
        "tripwire_version": __version__,
        "git_sha": git_sha(),
        "python": platform.python_version(),
        "date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "agent": agent,
        "model": model,
        "system_override": system_override,
        "n": n,
        "mutators": mutators,
        "attack_library_hash": attack_library_hash(attacks),
        "attack_count": len(attacks),
    }