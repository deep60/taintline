from dataclasses import replace

from tripwire.attacks import load_attacks
from tripwire.meta import attack_library_hash, collect


def test_hash_is_stable_under_reordering():
    atks = load_attacks()
    assert attack_library_hash(atks) == attack_library_hash(list(reversed(atks)))


def test_hash_changes_when_a_payload_changes():
    atks = load_attacks()
    changed = [replace(atks[0], payload=atks[0].payload + " extra")] + atks[1:]
    assert attack_library_hash(atks) != attack_library_hash(changed)


def test_collect_has_the_pins_we_need():
    atks = load_attacks()
    m = collect(agent="anthropic", model="x", system_override=True, n=3, attacks=atks,
                mutators=["base64"])
    for key in ("tripwire_version", "git_sha", "date_utc", "agent", "model", "system_override",
                "n", "attack_library_hash", "attack_count", "mutators", "python"):
        assert key in m
    assert m["model"] == "x" and m["system_override"] is True and m["attack_count"] == len(atks)