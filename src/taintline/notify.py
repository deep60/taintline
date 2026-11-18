"""Signed webhooks: tell another system when `monitor` sees drift or a live run delivers a leak.

Every request carries
    X-Taintline-Timestamp: unix seconds
    X-Taintline-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<raw body>">
    X-Taintline-Event:     drift | leak | invalid_run
so a receiver can reject forgeries and replays (`verify`). The secret comes from an environment
variable, never the command line. The destination must be in SCOPE.yaml like any other network
target, must be https (loopback http is allowed for local receivers), and redirects are not followed.

What this does NOT do: no host isolation, no revoking cloud credentials, no PagerDuty/Slack-specific
formatting. Point it at your own receiver or an automation tool's generic webhook trigger.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from urllib.parse import urlparse

from .report.frameworks import flat
from .report.sarif import Finding, fingerprint

LOOPBACK = {"localhost", "127.0.0.1", "::1"}
SCHEMA = "taintline.webhook/1"


class NotifyError(RuntimeError):
    pass


def sign(body: bytes, secret: str, timestamp: int) -> str:
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def verify(body: bytes, headers: dict, secret: str, tolerance: int = 300, now: float | None = None) -> bool:
    """For receivers: True only if the signature matches and the timestamp is fresh."""
    h = {k.lower(): v for k, v in headers.items()}
    try:
        ts = int(h["x-taintline-timestamp"])
        got = h["x-taintline-signature"]
    except (KeyError, ValueError):
        return False
    if abs((time.time() if now is None else now) - ts) > tolerance:
        return False
    return hmac.compare_digest(got, sign(body, secret, ts))


def build_event(kind: str, findings: list[Finding], source: str = "", now: float | None = None) -> dict:
    return {"schema": SCHEMA, "event": kind, "time": int((time.time() if now is None else now)),
            "source": source,
            "counts": {"findings": len(findings),
                       "errors": sum(f.level == "error" for f in findings)},
            "findings": [{"id": fingerprint(f), "rule": f.rule, "level": f.level, "message": f.message,
                          "server": f.server, "tool": f.tool, "frameworks": flat(f.rule)} for f in findings]}


def classify(findings: list[Finding]) -> str | None:
    """Which event (if any) these findings warrant."""
    if any(f.rule == "run/invalid" for f in findings):
        return "invalid_run"
    if any(f.rule == "dynamic/canary_delivered" for f in findings):
        return "leak"
    if any(f.rule.startswith("drift/") for f in findings):
        return "drift"
    return None


def _check_url(url: str) -> str:
    u = urlparse(url)
    if u.scheme not in ("https", "http") or not u.hostname:
        raise NotifyError(f"not a usable webhook URL: {url}")
    if u.scheme == "http" and u.hostname not in LOOPBACK:
        raise NotifyError("webhook must use https (plain http is allowed only for localhost)")
    return u.netloc


def send(gate, url: str, payload: dict, secret_env: str, timeout: float = 10.0, retries: int = 2,
         dry_run: bool = False, client=None) -> dict:
    """POST the signed payload. Returns {"status": int|None, "attempts": n, "dry_run": bool}."""
    gate.check_server(_check_url(url))
    secret = os.environ.get(secret_env)
    if not secret:
        raise NotifyError(f"environment variable {secret_env} is not set (it holds the signing secret)")
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    ts = int(time.time())
    headers = {"Content-Type": "application/json", "User-Agent": "taintline-webhook/1",
               "X-Taintline-Timestamp": str(ts), "X-Taintline-Signature": sign(body, secret, ts),
               "X-Taintline-Event": payload["event"]}
    if dry_run:
        return {"status": None, "attempts": 0, "dry_run": True, "bytes": len(body)}
    import httpx
    http = client or httpx.Client(timeout=timeout, follow_redirects=False)
    last: Exception | None = None
    for attempt in range(1, retries + 2):
        try:
            r = http.post(url, content=body, headers=headers)
            if r.status_code < 500:
                if r.status_code >= 300:
                    raise NotifyError(f"webhook receiver answered {r.status_code}")
                return {"status": r.status_code, "attempts": attempt, "dry_run": False}
            last = NotifyError(f"webhook receiver answered {r.status_code}")
        except httpx.HTTPError as e:
            last = e
        if attempt <= retries:
            time.sleep(min(2 ** (attempt - 1), 4))
    raise NotifyError(f"webhook not delivered after {retries + 1} attempt(s): {last}")
