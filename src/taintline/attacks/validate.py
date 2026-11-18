"""Check attack YAML so contributors can add attacks as data without running a model.
Returns a list of problems; empty means the file is usable."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from ..sandbox import ATTACKER_EMAIL, ATTACKER_URL
from .loader import Attack, load_attacks

SURFACES = {"tool_result", "tool_description", "native", "page", "email", "web", "file"}
LIVE_SURFACES = {"tool_result", "tool_description", "native", "page"}
PAGE_VECTORS = {"visible_text", "css_hidden", "offscreen", "white_on_white", "html_comment", "alt_text",
                "aria_label", "form_field", "hidden_input"}
TARGETS = {"api_key", "ssn"}
PLACEHOLDER = re.compile(r"\{[a-z_]+\}")


def validate_file(path: str | Path, subs: dict | None = None, tools: set | None = None,
                  servers: set | None = None, live: bool = True) -> list[str]:
    """`subs`/`tools`/`servers` come from a lab so placeholders and tool names can be checked."""
    problems: list[str] = []
    p = Path(path)
    files = sorted(p.glob("*.yaml")) if p.is_dir() else [p]
    if not files:
        return [f"{p}: no .yaml files"]
    for f in files:
        try:
            raw = yaml.safe_load(f.read_text()) or []
        except yaml.YAMLError as e:
            problems.append(f"{f.name}: not valid YAML ({e})")
            continue
        if not isinstance(raw, list):
            problems.append(f"{f.name}: top level must be a list of attacks")
            continue
        try:
            attacks = load_attacks(f, subs)
        except TypeError as e:
            problems.append(f"{f.name}: bad or missing field ({e})")
            continue
        except KeyError as e:
            problems.append(f"{f.name}: missing field {e}")
            continue
        for a in attacks:
            problems += [f"{f.name}:{a.id}: {m}" for m in _check(a, tools, servers, live)]
    ids = [a.id for f in files for a in _safe_load(f, subs)]
    problems += [f"duplicate attack id: {i}" for i in sorted({i for i in ids if ids.count(i) > 1})]
    return problems


def _safe_load(f, subs):
    try:
        return load_attacks(f, subs)
    except Exception:
        return []


def _check(a: Attack, tools: set | None, servers: set | None, live: bool) -> list[str]:
    out = []
    if not a.id or not re.fullmatch(r"[a-z0-9_+-]+", a.id):
        out.append("id must be lowercase letters, digits, _ + -")
    if a.surface not in (LIVE_SURFACES if live else SURFACES):
        out.append(f"surface '{a.surface}' not usable here (use one of {sorted(LIVE_SURFACES if live else SURFACES)})")
    if not 1 <= a.effort <= 5:
        out.append("effort must be 1..5")
    if a.target not in TARGETS:
        out.append(f"target must be one of {sorted(TARGETS)}")
    if a.surface in ("tool_result", "tool_description") and not a.target_tool:
        out.append(f"{a.surface} attacks need target_tool")
    if a.surface == "page" and (a.env or {}).get("PAGE_VECTOR") not in PAGE_VECTORS:
        out.append(f"page attacks need env PAGE_VECTOR, one of {sorted(PAGE_VECTORS)}")
    if a.surface != "native" and not (a.payload.strip() or a.parts):
        out.append("empty payload")
    if a.parts is not None and (not isinstance(a.parts, list) or not all(isinstance(x, str) and x.strip() for x in a.parts)):
        out.append("parts must be a list of non-empty strings")
    if a.parts and a.surface != "tool_result":
        out.append("parts (split payload) only work on the tool_result surface")
    if a.after and a.surface != "tool_result":
        out.append("after (delayed payload) only works on the tool_result surface")
    if not isinstance(a.after, int) or a.after < 0:
        out.append("after must be an integer >= 0")
    text = a.payload + " ".join(a.parts or [])
    left = PLACEHOLDER.findall(text) + PLACEHOLDER.findall(a.target_tool or "") + PLACEHOLDER.findall(a.server or "")
    if left:
        out.append(f"unresolved placeholders {sorted(set(left))}")
    if a.surface != "native" and ATTACKER_EMAIL not in text and ATTACKER_URL not in text and "evil.example" not in text:
        out.append("payload never names the attacker destination ({attacker_email}/{attacker_url}); it cannot cause a leak")
    if tools is not None and a.target_tool and a.target_tool not in tools:
        out.append(f"target_tool '{a.target_tool}' is not a tool of this lab ({sorted(tools)})")
    if servers is not None and a.server and a.server not in servers:
        out.append(f"server '{a.server}' is not part of this lab ({sorted(servers)})")
    return out
