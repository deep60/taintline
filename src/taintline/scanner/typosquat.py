"""Package names that look like a well-known MCP server but aren't it. Offline: a fixed list of
widely used packages, compared by edit distance. A config that runs `server-filesytem` or the
unscoped `server-filesystem` (not `@modelcontextprotocol/server-filesystem`) may be running
someone else's code with the same access.

It flags look-alikes of the names below only; it can't tell whether a package is malicious, and
it doesn't know packages that aren't listed. Check the publisher before trusting either way.
"""
from __future__ import annotations

KNOWN = {
    "npm": {
        "@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-memory",
        "@modelcontextprotocol/server-everything", "@modelcontextprotocol/server-sequential-thinking",
        "@modelcontextprotocol/server-github", "@modelcontextprotocol/server-brave-search",
        "@modelcontextprotocol/server-puppeteer", "@modelcontextprotocol/server-postgres",
        "@modelcontextprotocol/server-slack", "@modelcontextprotocol/server-gdrive",
        "@modelcontextprotocol/server-google-maps", "@modelcontextprotocol/server-redis",
        "@modelcontextprotocol/server-gitlab",
        "@modelcontextprotocol/inspector", "@playwright/mcp", "@upstash/context7-mcp",
        "@notionhq/notion-mcp-server", "@supabase/mcp-server-supabase", "@sentry/mcp-server",
        "@browserbasehq/mcp", "@stripe/mcp", "firecrawl-mcp", "tavily-mcp", "exa-mcp-server",
        "mcp-remote", "figma-developer-mcp", "@wonderwhy-er/desktop-commander",
    },
    "pypi": {
        "mcp-server-fetch", "mcp-server-git", "mcp-server-time", "mcp-server-sqlite", "mcp", "fastmcp",
    },
}


def distance(a: str, b: str) -> int:
    """Edit distance counting a swap of neighbours as one edit (optimal string alignment)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def bare_name(spec: str, eco: str) -> str:
    """Drop the version: @scope/pkg@1.2 -> @scope/pkg, pkg==1.2 -> pkg."""
    if eco == "npm":
        at = spec.rfind("@")
        return spec[:at] if at > 0 else spec
    for sep in ("==", ">=", "<=", "~=", "@", "["):
        spec = spec.split(sep)[0]
    return spec.strip()


def look_alike(spec: str, eco: str) -> tuple[str, str] | None:
    """(kind, message) when `spec` imitates a known package, else None."""
    known = KNOWN.get(eco)
    if not known:
        return None
    name = bare_name(spec, eco).lower()
    if name in known:
        return None
    for k in sorted(known):
        if "/" in k and name == k.split("/", 1)[1]:
            return ("scope_confusion", f"'{name}' is the bare name of '{k}'; without the scope it can be "
                                       "anyone's package")
    # an npm scope belongs to one publisher: '@org/x' can't squat '@org/y', only a look-alike scope can
    scope = name.split("/", 1)[0] if name.startswith("@") and "/" in name else None
    candidates = [k for k in known if not (scope and k.startswith(scope + "/"))]
    if not candidates:
        return None
    best = min(candidates, key=lambda k: distance(name, k))
    dist = distance(name, best)
    if 0 < dist <= (1 if len(best) < 8 else 2):
        return ("possible_typosquat", f"'{name}' is {dist} character(s) away from the well-known '{best}'")
    return None
