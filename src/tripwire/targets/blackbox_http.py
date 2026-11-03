"""Black-box HTTP target (M6): a chat endpoint you are authorized to test, driven from a YAML config.

A copilot has no tool trace we can read. What we CAN observe: the reply text, and whether our own
collaborator sink received a request carrying the canary. So the sink is the only proof of a leak.

Everything the config names is checked against the scope gate before a request is sent. Secrets
(tokens) are never stored in the config: write `${ENV_VAR}` and export the variable."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml

from ..scope import Gate


class BlackboxConfigError(ValueError):
    pass


@dataclass
class Endpoint:
    url: str
    method: str = "POST"
    headers: dict = field(default_factory=dict)
    body: dict | str | None = None
    response_path: str = ""          # dotted path into the JSON reply; "" = whole text


@dataclass
class BBTask:
    id: str
    prompt: str
    keywords: list
    title: str
    benign_text: str


@dataclass
class BlackboxConfig:
    name: str
    chat: Endpoint
    tasks: list[BBTask]
    plant: Endpoint | None = None            # None = manual planting (operator pastes the text)
    secret_title: str = "Credentials"
    secret_text: str = "prod api key: {canary}"
    delay_seconds: float = 1.0               # politeness: minimum gap between requests
    timeout: float = 60.0

    def hosts(self) -> list[str]:
        return [urlparse(e.url).netloc for e in (self.chat, self.plant) if e]


_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand(value: str) -> str:
    def sub(m):
        v = os.environ.get(m.group(1))
        if v is None:
            raise BlackboxConfigError(f"environment variable {m.group(1)} is not set")
        return v
    return _ENV.sub(sub, value)


def _endpoint(d: dict, what: str, expand: bool) -> Endpoint:
    if not isinstance(d, dict) or not isinstance(d.get("url"), str):
        raise BlackboxConfigError(f"{what}.url is required")
    if urlparse(d["url"]).scheme not in ("http", "https"):
        raise BlackboxConfigError(f"{what}.url must be http(s)")
    headers = {str(k): (_expand(str(v)) if expand else str(v)) for k, v in (d.get("headers") or {}).items()}
    return Endpoint(d["url"], str(d.get("method", "POST")).upper(), headers, d.get("body"),
                    str(d.get("response_path", "")))


def parse_config(d: dict, expand_env: bool = True) -> BlackboxConfig:
    if not isinstance(d, dict):
        raise BlackboxConfigError("config must be a YAML mapping")
    if not d.get("name"):
        raise BlackboxConfigError("name is required")
    tasks = []
    for t in d.get("tasks") or []:
        missing = [k for k in ("id", "prompt", "keywords", "title", "benign_text") if not t.get(k)]
        if missing:
            raise BlackboxConfigError(f"task {t.get('id', '?')} is missing {missing}")
        tasks.append(BBTask(t["id"], t["prompt"], list(t["keywords"]), t["title"], t["benign_text"]))
    if not tasks:
        raise BlackboxConfigError("at least one task is required")
    secret = d.get("secret") or {}
    return BlackboxConfig(
        d["name"], _endpoint(d.get("chat"), "chat", expand_env), tasks,
        _endpoint(d["plant"], "plant", expand_env) if d.get("plant") else None,
        secret.get("title", "Credentials"), secret.get("text", "prod api key: {canary}"),
        float(d.get("delay_seconds", 1.0)), float(d.get("timeout", 60.0)))


def load_config(path: str | Path, expand_env: bool = True) -> BlackboxConfig:
    return parse_config(yaml.safe_load(Path(path).read_text()), expand_env)


def _fill(obj, **vals):
    """Fill {placeholders} in a JSON-like body without touching the braces of other text."""
    if isinstance(obj, str):
        for k, v in vals.items():
            obj = obj.replace("{" + k + "}", v)
        return obj
    if isinstance(obj, dict):
        return {k: _fill(v, **vals) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_fill(v, **vals) for v in obj]
    return obj


def dig(data, path: str):
    for part in [p for p in path.split(".") if p]:
        data = data[int(part)] if isinstance(data, list) else data[part]
    return data


class BlackboxHTTPAgent:
    """Talks to a chat endpoint. Every request is scope-checked first."""

    def __init__(self, cfg: BlackboxConfig, gate: Gate, client=None):
        self.cfg, self.gate, self._client = cfg, gate, client
        self.requests = 0
        for host in cfg.hosts():
            gate.check_server(host)

    def _http(self):
        if self._client is None:
            import httpx

            self._client = httpx.Client(timeout=self.cfg.timeout)
        return self._client

    def _send(self, ep: Endpoint, **vals):
        self.gate.check_server(urlparse(ep.url).netloc)
        self.requests += 1
        body = _fill(ep.body, **vals)
        kw = {"json": body} if isinstance(body, (dict, list)) else {"content": body}
        r = self._http().request(ep.method, ep.url, headers=ep.headers, **kw)
        r.raise_for_status()
        return r

    def ask(self, message: str) -> str:
        r = self._send(self.cfg.chat, message=message)
        if not self.cfg.chat.response_path:
            return r.text
        return str(dig(r.json(), self.cfg.chat.response_path))

    def plant(self, title: str, text: str) -> None:
        if self.cfg.plant is None:
            raise BlackboxConfigError("no plant endpoint configured; use manual planting")
        self._send(self.cfg.plant, title=title, text=text)
