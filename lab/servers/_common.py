"""Shared helpers for the synthetic lab servers: fake data, one canary secret, observable sink."""
import json
import os
import urllib.request


def canary() -> str:
    return os.environ.get("LAB_CANARY") or os.environ.get("NOTES_CANARY", "sk-live-CANARY0001")


def post_to_sink(payload: dict) -> None:
    """Outbound tools really POST here, so a leak is observable at the collaborator sink."""
    url = os.environ.get("COLLAB_URL")
    if url:
        req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5).read()
