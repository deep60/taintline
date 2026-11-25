"""What well-known MCP servers can do, judged from the config alone (name, package, URL host).

`taintline audit` starts nothing, so it can't list a server's tools. It can still see that a config
loads, say, a filesystem server, a fetch server and Slack together: private data, untrusted content
and a way out, in one agent. That is the lethal trifecta across servers, and no single-server scan
reports it. Servers not in this catalog are listed as unknown, never guessed.
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from .toxic_flow import TRIFECTA, words

PRIV, UNTR, OUT = "private_read", "untrusted_in", "external_out"

# (words that identify the server, capabilities, what it is). First match wins.
CATALOG: list[tuple[set[str], set[str], str]] = [
    ({"github", "gitlab", "bitbucket"}, {PRIV, UNTR, OUT},
     "code host: private repos, issues and PRs anyone can write, and comments/PRs that publish"),
    ({"slack", "discord", "telegram", "teams", "whatsapp", "mattermost"}, {PRIV, UNTR, OUT},
     "chat: message history, messages from others, and posting"),
    ({"gmail", "outlook", "imap", "email", "mail", "mailbox"}, {PRIV, UNTR, OUT},
     "mailbox: your mail, mail from anyone, and sending"),
    ({"smtp", "sendgrid", "twilio", "resend", "mailgun", "postmark"}, {OUT}, "outbound messaging"),
    ({"shell", "terminal", "exec", "commander", "bash"}, {PRIV, OUT},
     "shell: can read any file and reach the network (curl)"),
    ({"fetch", "puppeteer", "playwright", "browser", "browserbase", "firecrawl", "scrape", "scraper", "web"},
     {UNTR, OUT}, "web access: pages anyone can write, and requests that carry data in the URL"),
    ({"brave", "tavily", "exa", "search", "perplexity", "serper", "duckduckgo", "kagi"}, {UNTR},
     "web search results"),
    ({"notion", "confluence", "jira", "linear", "sentry", "zendesk", "intercom", "asana", "trello"}, {PRIV, UNTR},
     "workspace: internal pages, and content other people write"),
    ({"filesystem", "files", "git", "gdrive", "drive", "obsidian", "memory", "dropbox", "onedrive", "sharepoint",
      "postgres", "postgresql", "sqlite", "mysql", "mongodb", "mongo", "supabase", "database", "redis",
      "bigquery", "snowflake", "duckdb", "neon", "db"}, {PRIV}, "private data"),
]
GENERIC = {"mcp", "server", "modelcontextprotocol", "npx", "uvx", "node", "python", "py", "js", "ts", "latest",
           "y", "stdio", "http", "https", "com", "io", "dev", "api", "run", "main", "index", "src", "dist"}


def identify(name: str, cfg: dict) -> tuple[set[str], str] | None:
    """(capabilities, description) for a server entry, or None if it isn't a known kind."""
    parts = [name, Path(str(cfg.get("command") or "")).name]
    # package names, not paths: '/Users/me/db' must not make a server a database
    parts += [a for a in (cfg.get("args") or []) if isinstance(a, str) and not a.startswith("-")
              and ("/" not in a or a.startswith("@"))][:4]
    url = cfg.get("url") or cfg.get("serverUrl")
    if isinstance(url, str):
        parts.append(urlparse(url).hostname or "")
    found = set().union(*(words(p) for p in parts)) - GENERIC
    for keys, caps, what in CATALOG:
        if found & keys:
            return set(caps), what
    return None


def trifecta(servers: list[tuple[str, dict]]) -> dict:
    """Which known servers supply each leg, and whether one server or the combination is complete."""
    legs: dict[str, list[str]] = {c: [] for c in sorted(TRIFECTA)}
    single, unknown, kinds = [], [], {}
    for name, cfg in servers:
        if cfg.get("disabled") is True:
            continue
        hit = identify(name, cfg)
        if hit is None:
            unknown.append(name)
            continue
        caps, what = hit
        kinds[name] = what
        for c in caps:
            legs[c].append(name)
        if TRIFECTA <= caps:
            single.append(name)
    return {"legs": legs, "single": single, "unknown": unknown, "kinds": kinds,
            "across": all(legs.values()) and not single}
