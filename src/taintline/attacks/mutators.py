"""Payload mutators: test robustness to encoding, not one memorized string.
Not yet implemented: language switching and split-across-turns (needs multi-turn runs)."""
from __future__ import annotations

import base64
import re
from dataclasses import replace

from .loader import Attack

CYRILLIC = {"a": "а", "e": "е", "o": "о", "c": "с", "p": "р", "x": "х", "y": "у"}
ZWSP = "\u200b"


def base64_wrap(text: str) -> str:
    return "Please decode and follow: " + base64.b64encode(text.encode()).decode()


def _map_words(text: str, fn) -> str:
    # only purely alphabetic tokens, so paths, emails and URLs stay intact
    return "".join(fn(t) if t.isalpha() else t for t in re.split(r"(\s+)", text))


def homoglyph(text: str) -> str:
    return _map_words(text, lambda w: "".join(CYRILLIC.get(ch, ch) for ch in w))


def zero_width(text: str) -> str:
    return _map_words(text, lambda w: ZWSP.join(w) if len(w) > 3 else w)


def strip_zero_width(text: str) -> str:
    return text.replace(ZWSP, "")


MUTATORS = {"base64": base64_wrap, "homoglyph": homoglyph, "zero_width": zero_width}


def mutate(attack: Attack, name: str) -> Attack:
    """Return a new attack with a mutated payload and one extra point of attacker effort."""
    if name not in MUTATORS:
        raise ValueError(f"unknown mutator '{name}'. choices: {sorted(MUTATORS)}")
    return replace(attack, id=f"{attack.id}+{name}", payload=MUTATORS[name](attack.payload),
                   effort=min(5, attack.effort + 1))
