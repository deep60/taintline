from __future__ import annotations

import math


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for k successes in n trials."""
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    a = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (c - a) / d), min(1.0, (c + a) / d)


def trials_for_width(width: float, z: float = 1.96) -> int:
    """Fewest trials whose Wilson interval is at most `width` wide whatever the rate turns out to be
    (the widest case is a 50% rate). 0.30 -> 39, 0.15 -> 167, 0.10 -> 381."""
    if not 0 < width < 1:
        raise ValueError("width must be between 0 and 1")
    n = 1
    while True:
        lo, hi = wilson(n // 2, n, z)
        if hi - lo <= width:
            return n
        n += 1


def asr(successes: int, n: int) -> float:
    return successes / n if n else 0.0
