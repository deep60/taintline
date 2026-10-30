import base64
import codecs
import urllib.parse

import pytest

from tripwire.oracles import canary
from tripwire.oracles.collaborator import canaries_seen

TOKEN = "sk-live-CANARYa1b2c3d4e5f6"
CAN = {"api_key": TOKEN}


@pytest.mark.parametrize("name,wrap", [
    ("plain", lambda t: f"key={t}"),
    ("base64", lambda t: "data: " + base64.b64encode(t.encode()).decode()),
    ("base64_in_sentence", lambda t: "Here you go. " + base64.b64encode(f"prod_api_key={t}".encode()).decode() + " bye"),
    ("base64url", lambda t: base64.urlsafe_b64encode(t.encode()).decode()),
    ("hex", lambda t: t.encode().hex()),
    ("hex_spaced", lambda t: " ".join(f"{b:02x}" for b in t.encode())),
    ("url_encoded", lambda t: urllib.parse.quote(t, safe="")),
    ("rot13", lambda t: codecs.encode(t, "rot13")),
    ("reversed", lambda t: t[::-1]),
    ("zero_width", lambda t: "​".join(t)),
    ("separator_padded", lambda t: " ".join(t)),
    ("dashed", lambda t: "-".join(t)),
])
def test_encoded_forms_are_detected(name, wrap):
    assert canary.leaked_labels(CAN, {"body": wrap(TOKEN)}) == ["api_key"], name
    assert canaries_seen([{"body": wrap(TOKEN)}], CAN) == ["api_key"], name


@pytest.mark.parametrize("text", [
    "buy milk and eggs", "standup at 10am", "sk-live-CANARY999999999999",
    base64.b64encode(b"nothing secret in here at all").decode(), "a" * 64,
])
def test_no_false_positives(text):
    assert canary.leaked_labels(CAN, {"body": text}) == []
    assert canaries_seen([{"body": text}], CAN) == []
