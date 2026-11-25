"""Lethal-trifecta analysis: private data + untrusted input + a way out.

A tool's capabilities come from what it can be asked to do, read from its name split into words
(read_email -> read, email) and its input-schema parameter names (url, to, sql, path). The
description is a fallback for tools whose name and schema say nothing. Whole words only: "notes"
in a description, or "http" in "uses the weather HTTP API", is not a capability.

Still a heuristic: it is triage for `taintline session` / `live-suite`, which prove or refute it.
"""
from __future__ import annotations

import re

TRIFECTA = {"private_read", "untrusted_in", "external_out"}

OUT_VERBS = {"send", "upload", "publish", "forward", "notify", "share", "reply", "tweet", "transmit",
             "submit", "webhook"}
# verbs that are also nouns: http_post / email_user send, but get_post / read_email read
MAYBE_OUT_VERBS = {"post", "email", "message", "dm", "sms", "push"}
FETCH_VERBS = {"fetch", "browse", "scrape", "crawl", "download", "navigate", "open", "visit", "click"}
READ_VERBS = {"read", "get", "list", "query", "search", "find", "lookup", "view", "show", "select",
              "retrieve", "load", "cat", "tail", "head", "grep", "describe"}
UNTRUSTED_OBJECTS = {"url", "page", "pages", "web", "website", "html", "link", "email", "emails", "mail",
                     "inbox", "message", "messages", "issue", "issues", "comment", "comments", "feed", "rss",
                     "tweet", "tweets", "chat", "channel", "post", "posts", "ticket", "tickets", "review"}
PRIVATE_OBJECTS = {"file", "files", "note", "notes", "doc", "docs", "document", "documents", "db", "database",
                   "table", "tables", "record", "records", "secret", "secrets", "credential", "credentials",
                   "key", "keys", "drive", "folder", "directory", "dir", "repo", "repository", "calendar",
                   "event", "events", "contact", "contacts", "customer", "customers", "row", "rows", "memory",
                   "email", "emails", "mail", "inbox", "message", "messages", "account", "accounts", "user",
                   "users", "env", "config", "storage", "cookie", "cookies", "session", "token", "tokens",
                   "history", "clipboard"}
URL_PARAMS = {"url", "uri", "href", "link", "endpoint", "webhook", "webhook_url", "callback_url", "target_url"}
RECIPIENT_PARAMS = {"to", "recipient", "recipients", "cc", "bcc", "channel", "channel_id", "chat_id", "phone",
                    "phone_number", "email_address", "address"}
PRIVATE_PARAMS = {"path", "file", "filename", "file_path", "filepath", "sql", "query_sql", "table", "table_name",
                  "dir", "directory", "folder"}


def words(text: str) -> set[str]:
    """read_email / readEmail / read-email -> {'read', 'email'}."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text or "")
    return {w.lower() for w in re.split(r"[^A-Za-z0-9]+", spaced) if w}


def _params(tool: dict) -> set[str]:
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    props = schema.get("properties") if isinstance(schema, dict) else None
    return {str(p).lower() for p in props} if isinstance(props, dict) else set()


def _classify(name_words: set[str], params: set[str]) -> dict[str, str]:
    caps: dict[str, str] = {}
    reading = bool(name_words & READ_VERBS)
    fetching = bool(name_words & FETCH_VERBS)
    sends = name_words & OUT_VERBS or (set() if reading or fetching else name_words & MAYBE_OUT_VERBS)
    if sends:
        caps["external_out"] = f"name says it sends ({', '.join(sorted(sends))})"
    elif params & RECIPIENT_PARAMS and not reading:
        caps["external_out"] = f"takes a recipient ({', '.join(sorted(params & RECIPIENT_PARAMS))})"
    if params & URL_PARAMS:
        caps.setdefault("external_out", "requests any URL it is given, so data can leave in the URL")
    if fetching:
        caps["untrusted_in"] = f"name says it fetches ({', '.join(sorted(name_words & FETCH_VERBS))})"
    elif params & URL_PARAMS and not sends:
        caps["untrusted_in"] = "reads whatever URL it is given"
    elif reading and name_words & UNTRUSTED_OBJECTS:
        caps["untrusted_in"] = f"reads content others write ({', '.join(sorted(name_words & UNTRUSTED_OBJECTS))})"
    if reading and (name_words & PRIVATE_OBJECTS or params & PRIVATE_PARAMS):
        what = sorted((name_words & PRIVATE_OBJECTS) | (params & PRIVATE_PARAMS))
        caps["private_read"] = f"reads stored data ({', '.join(what)})"
    elif params & {"sql", "query_sql"}:
        caps["private_read"] = "runs queries against stored data"
    return caps


def explain(tool: dict) -> dict[str, str]:
    """{capability: why} for one tool."""
    caps = _classify(words(tool.get("name", "")), _params(tool))
    if not caps:                       # name and schema were silent: fall back to the first sentence
        first = re.split(r"(?<=[.!?])\s", tool.get("description") or "", maxsplit=1)[0]
        caps = {k: v + " (from the description)" for k, v in _classify(words(first), set()).items()}
    return caps


def capabilities(tool: dict) -> set[str]:
    return set(explain(tool))


def analyze(tools: list[dict]) -> dict:
    caps: set[str] = set()
    evidence: dict[str, list[str]] = {}
    for t in tools:
        for cap in explain(t):
            caps.add(cap)
            evidence.setdefault(cap, []).append(t.get("name", ""))
    return {"capabilities": sorted(caps), "trifecta_complete": TRIFECTA <= caps,
            "evidence": {k: sorted(set(v)) for k, v in sorted(evidence.items())}}
