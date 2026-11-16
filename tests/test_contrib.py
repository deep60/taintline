"""Contribution gate: every bundled attack file and every starter in examples/attacks must validate
against the labs it is meant for. CI runs this on every PR."""
from pathlib import Path

import pytest

from tripwire.attacks.validate import validate_file
from tripwire.labs import GENERIC, LABS

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "attacks"
TEMPLATE_LABS = [n for n, lab in LABS.items() if lab.attack_file is None]


def _check(path, lab):
    tools = {lab.inject_tool} if lab.inject_tool else None
    return validate_file(path, lab.subs(), tools, set(lab.servers))


@pytest.mark.parametrize("name", sorted(LABS))
def test_every_lab_attack_file_validates(name):
    lab = LABS[name]
    assert _check(lab.attack_file or GENERIC, lab) == []


@pytest.mark.parametrize("starter,labs", [
    ("01_notes_calendar_invite.yaml", ["notes"]),
    ("02_generic_tool_description.yaml", TEMPLATE_LABS),
    ("03_browser_aria_label.yaml", ["browser"]),
])
def test_starter_attacks_validate_in_their_labs(starter, labs):
    assert labs
    for name in labs:
        assert _check(EXAMPLES / starter, LABS[name]) == [], name


def test_every_starter_is_covered_and_documented():
    starters = sorted(p.name for p in EXAMPLES.glob("*.yaml"))
    guide = (ROOT / "CONTRIBUTING.md").read_text()
    assert len(starters) == 3 and all(s in guide for s in starters)


def test_starter_ids_do_not_collide_with_the_library():
    from tripwire.attacks import load_attacks
    library = {a.id for lab in LABS.values() for a in lab.attacks()}
    for p in EXAMPLES.glob("*.yaml"):
        assert not {a.id for a in load_attacks(p)} & library, p.name


def _leaderboard():
    import importlib.util
    spec = importlib.util.spec_from_file_location("build_leaderboard", ROOT / "scripts" / "build_leaderboard.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_leaderboard_page_matches_the_snapshots():
    lb = _leaderboard()
    assert (lb.OUT / "README.md").read_text() == lb.build(), "run scripts/build_leaderboard.py"


def test_overlapping_intervals_share_a_tier_and_invalid_runs_are_not_ranked():
    lb = _leaderboard()
    rows = [{"ci": (0.01, 0.10)}, {"ci": (0.05, 0.15)}, {"ci": (0.20, 0.40)}, {"ci": (0.30, 0.50)}]
    assert lb.tiers(rows) == [1, 1, 2, 2]
    page = (lb.OUT / "README.md").read_text()
    ranked = page.split("Not ranked")[0]
    for r in lb.load_runs():
        if not r["valid"]:
            assert f"`{r['run']}` |" not in ranked
