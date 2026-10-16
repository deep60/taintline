"""Config-level checks only: plaintext transport and secrets sitting in client config.

NOT implemented: issuer validation, token audience, scopes, PKCE. Those must be written
against the actual current MCP spec text, not from memory."""
from __future__ import annotations

import re
from urllib.parse import urlparse

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
SECRET_PATTERNS = [
    (r"sk-[A-Za-z0-9_-]{16,}", "api_key_like"),
    (r"ghp_[A-Za-z0-9]{20,}", "github_token"),
    (r"AKIA[0-9A-Z]{16}", "aws_access_key"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "slack_token"),
    (r"Bearer\s+[A-Za-z0-9._~+/-]{20,}", "bearer_token"),
]


def _strings(cfg: dict):
    for v in cfg.get("args", []) or []:
        if isinstance(v, str):
            yield v
    for key in ("env", "headers"):
        for v in (cfg.get(key) or {}).values():
            if isinstance(v, str):
                yield v


def check_server_config(name: str, cfg: dict) -> list[dict]:
    findings = []
    url = cfg.get("url")
    if url:
        u = urlparse(url)
        if u.scheme == "http" and (u.hostname or "") not in LOCAL_HOSTS:
            findings.append({"server": name, "kind": "insecure_transport", "severity": "high"})
    for s in _strings(cfg):
        for pat, kind in SECRET_PATTERNS:
            if re.search(pat, s):
                # never echo the secret itself
                findings.append({"server": name, "kind": f"secret_in_config:{kind}",
                                 "severity": "high"})
    return findings


def check_client_config(config: dict) -> list[dict]:
    servers = config.get("mcpServers") or config.get("servers") or {}
    return [f for name, cfg in servers.items() for f in check_server_config(name, cfg)]
