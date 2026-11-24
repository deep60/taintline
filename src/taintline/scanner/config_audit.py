"""`taintline audit`: find the MCP client configs on this machine (or in a repo) and check each server
entry without starting anything.

Static checks only. Nothing here runs a server, resolves a package or touches the network:
  secret_in_config        a token-shaped string sits in args, env, headers or the URL       high
  insecure_transport      a remote server is reached over plain http                        high
  credential_in_config    an env var named like a credential holds a literal value          medium
  unpinned_package        npx/uvx/pipx/bunx/docker fetches a package with no fixed version  medium
  broad_filesystem        a server is handed / or the home folder                           medium
  mutable_image_tag       a docker image is pinned by tag, not digest                       low
  auto_approved_tools     tools are set to run without asking the user                      low
  lethal_trifecta_in_server       one known server reads private data, takes in untrusted
                                  content and sends data out (GitHub, Slack, a mailbox)     medium
  lethal_trifecta_across_servers  the servers one agent loads cover all three between them  medium

The trifecta checks recognize well-known servers by name and package (scanner/server_catalog.py);
unknown servers are left out, never guessed. Findings that can be tested carry a `prove` command
(scanner/prove.py): a `taintline session` lab with the same shape, or `monitor`.

Secret values are never printed or stored: a finding names the server, the field and the kind.
Client config locations change between releases, so DISCOVERY is a best-known list, not a promise;
pass paths explicitly when in doubt."""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from .auth_checks import LOCAL_HOSTS
from .prove import proof_for
from .server_catalog import trifecta

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}

SECRET_PATTERNS = [
    (r"sk-[A-Za-z0-9_-]{16,}", "api_key_like"),
    (r"gh[pousr]_[A-Za-z0-9]{20,}", "github_token"),
    (r"github_pat_[A-Za-z0-9_]{20,}", "github_token"),
    (r"glpat-[A-Za-z0-9_-]{20,}", "gitlab_token"),
    (r"AKIA[0-9A-Z]{16}", "aws_access_key"),
    (r"AIza[0-9A-Za-z_-]{35}", "google_api_key"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "slack_token"),
    (r"Bearer\s+[A-Za-z0-9._~+/-]{20,}", "bearer_token"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private_key"),
]
CRED_NAME = re.compile(r"(TOKEN|SECRET|PASSW(OR)?D|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH)", re.I)
# values that point elsewhere instead of holding the secret: ${VAR}, ${env:VAR}, ${input:x}, $VAR, {env:X}
REFERENCE = re.compile(r"^\s*(\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|\{env:[^}]+\})\s*$")
PLACEHOLDER = re.compile(r"(your[-_ ]|<[^>]+>|x{4,}|changeme|replace[-_ ]?me|\.\.\.|^\*+$)", re.I)
URL_SECRET_PARAMS = re.compile(r"(token|key|secret|password|auth|sig)", re.I)

RUNNERS = {"npx", "bunx", "pnpx", "uvx", "pipx", "docker", "podman"}
DOCKER_VALUE_FLAGS = {"-e", "--env", "-v", "--volume", "--name", "--network", "-p", "--publish", "--mount",
                      "-w", "--workdir", "-u", "--user", "--env-file", "--entrypoint", "--platform", "-l",
                      "--label", "--add-host", "--cpus", "-m", "--memory", "--pull", "--hostname", "-h"}
NPM_VALUE_FLAGS = {"-p", "--package", "--registry", "--cache", "--prefix"}
UV_VALUE_FLAGS = {"--with", "--python", "-p", "--index", "--index-url", "--extra-index-url", "--from"}


def _home_variants() -> set[str]:
    h = str(Path.home())
    return {"/", "~", "~/", "$HOME", "${HOME}", "${env:HOME}", "${userHome}", h, h + "/", "C:\\", "C:/",
            "%USERPROFILE%"}


@dataclass
class AuditFinding:
    file: str
    line: int
    client: str
    server: str
    kind: str
    severity: str
    message: str
    fix: str
    prove: dict | None = None        # {"command", "why"}: how to test this finding dynamically


# -- discovery ------------------------------------------------------------------------------------
def _user_locations() -> list[tuple[str, Path]]:
    home = Path.home()
    appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
    mac = home / "Library" / "Application Support"
    xdg = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
    return [
        ("Claude Desktop", mac / "Claude" / "claude_desktop_config.json"),
        ("Claude Desktop", xdg / "Claude" / "claude_desktop_config.json"),
        ("Claude Desktop", appdata / "Claude" / "claude_desktop_config.json"),
        ("Claude Code", home / ".claude.json"),
        ("Cursor", home / ".cursor" / "mcp.json"),
        ("VS Code", mac / "Code" / "User" / "mcp.json"),
        ("VS Code", xdg / "Code" / "User" / "mcp.json"),
        ("VS Code", appdata / "Code" / "User" / "mcp.json"),
        ("Windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"),
    ]


PROJECT_FILES = [("Claude Code", ".mcp.json"), ("Cursor", ".cursor/mcp.json"), ("VS Code", ".vscode/mcp.json"),
                 ("generic", "mcp.json")]


def discover(project: str | Path | None = ".", user: bool = True) -> list[tuple[str, Path]]:
    found: list[tuple[str, Path]] = []
    if user:
        found += [(c, p) for c, p in _user_locations() if p.is_file()]
    if project is not None:
        root = Path(project)
        found += [(c, root / rel) for c, rel in PROJECT_FILES if (root / rel).is_file()]
    seen, out = set(), []
    for c, p in found:
        key = p.resolve()
        if key not in seen:
            seen.add(key)
            out.append((c, p))
    return out


def guess_client(path: Path) -> str:
    s = str(path).replace("\\", "/")
    for needle, client in (("claude_desktop_config", "Claude Desktop"), (".claude.json", "Claude Code"),
                           (".mcp.json", "Claude Code"), (".cursor/", "Cursor"), ("/Code/", "VS Code"),
                           (".vscode/", "VS Code"), ("windsurf", "Windsurf")):
        if needle in s:
            return client
    return "generic"


# -- parsing --------------------------------------------------------------------------------------
def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas (VS Code configs allow both), leaving strings intact."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
            out.append(ch)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            nl = text.count("\n", i, n if end < 0 else end)
            out.append("\n" * nl)                 # keep line numbers stable
            i = n if end < 0 else end + 2
            continue
        else:
            out.append(ch)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def servers_in(doc: dict) -> list[tuple[str, str, dict]]:
    """(where, name, cfg) for every server block the known clients use."""
    out = []

    def take(where: str, block):
        if isinstance(block, dict):
            out.extend((where, n, c) for n, c in block.items() if isinstance(c, dict))

    take("mcpServers", doc.get("mcpServers"))
    take("servers", doc.get("servers"))
    if isinstance(doc.get("mcp"), dict):
        take("mcp.servers", doc["mcp"].get("servers"))
    for proj, body in (doc.get("projects") or {}).items():      # ~/.claude.json keeps per-project servers
        if isinstance(body, dict):
            take(f"projects[{proj}].mcpServers", body.get("mcpServers"))
    return out


def _line_of(text: str, name: str, start: int = 0) -> int:
    m = re.compile(rf'"{re.escape(name)}"\s*:').search(text, start)
    return text.count("\n", 0, m.start()) + 1 if m else 1


# -- checks ---------------------------------------------------------------------------------------
def _package_spec(cmd: str, args: list[str]) -> tuple[str | None, str]:
    """(package spec or None, ecosystem) for a runner command."""
    rest = list(args)
    if cmd == "pipx":
        if not rest or rest[0] != "run":
            return None, "pypi"
        rest = rest[1:]
    if cmd in ("docker", "podman"):
        if "run" not in rest:
            return None, "docker"
        rest = rest[rest.index("run") + 1:]
        flags = DOCKER_VALUE_FLAGS
    elif cmd in ("uvx", "pipx"):
        if "--from" in rest and rest.index("--from") + 1 < len(rest):
            return rest[rest.index("--from") + 1], "pypi"
        flags = UV_VALUE_FLAGS
    else:
        if "-p" in rest or "--package" in rest:
            i = rest.index("-p") if "-p" in rest else rest.index("--package")
            return (rest[i + 1] if i + 1 < len(rest) else None), "npm"
        flags = NPM_VALUE_FLAGS
    skip = False
    for a in rest:
        if skip:
            skip = False
            continue
        if a.startswith("-"):
            skip = a in flags and "=" not in a
            continue
        return a, ("docker" if cmd in ("docker", "podman") else "pypi" if cmd in ("uvx", "pipx") else "npm")
    return None, ""


def _pin_state(spec: str, eco: str) -> str:
    """'pinned', 'tag' (docker tag, mutable), or 'unpinned'."""
    if eco == "npm":
        at = spec.rfind("@")
        if at <= 0:                               # no @, or only the scope's leading @
            return "unpinned"
        ver = spec[at + 1:]
        return "unpinned" if ver in ("", "latest", "next", "*") or ver.startswith(("^", "~", ">")) else "pinned"
    if eco == "pypi":
        if spec.startswith(("git+", "http://", "https://", ".", "/")):
            return "pinned" if re.search(r"@[0-9a-f]{40}$", spec) else "unpinned"
        return "pinned" if re.search(r"(==|@)\s*[\w.]+$", spec) else "unpinned"
    if eco == "docker":
        if "@sha256:" in spec:
            return "pinned"
        name = spec.rsplit("/", 1)[-1]
        if ":" not in name or name.endswith(":latest"):
            return "unpinned"
        return "tag"
    return "pinned"


def check_server(name: str, cfg: dict) -> list[tuple[str, str, str, str]]:
    """[(kind, severity, message, fix)] for one server entry. Never includes a secret's value."""
    out = []
    args = [a for a in (cfg.get("args") or []) if isinstance(a, str)]
    env = {k: v for k, v in (cfg.get("env") or {}).items() if isinstance(v, str)}
    headers = {k: v for k, v in (cfg.get("headers") or {}).items() if isinstance(v, str)}
    url = cfg.get("url") or cfg.get("serverUrl") or ""
    url = url if isinstance(url, str) else ""

    if url:
        u = urlparse(url)
        if u.scheme == "http" and (u.hostname or "") not in LOCAL_HOSTS:
            out.append(("insecure_transport", "high", f"remote server reached over plain http ({u.hostname})",
                        "use https; anything on the wire, including tokens and tool results, is readable"))
        for k, v in parse_qsl(u.query):
            if URL_SECRET_PARAMS.search(k) and v and not REFERENCE.match(v) and not PLACEHOLDER.search(v):
                out.append(("secret_in_config", "high", f"credential-like query parameter '{k}' in the URL",
                            "move it to a header that reads from an env var; URLs end up in logs"))

    fields = [(f"args[{i}]", a) for i, a in enumerate(args)] + [(f"env.{k}", v) for k, v in env.items()] + \
             [(f"headers.{k}", v) for k, v in headers.items()] + ([("url", url)] if url else [])
    flagged = set()
    for where, val in fields:
        for pat, kind in SECRET_PATTERNS:
            if re.search(pat, val):
                out.append(("secret_in_config", "high", f"{kind.replace('_', ' ')} in {where}",
                            "rotate it, then reference an env var (e.g. ${env:NAME}) instead of pasting the value"))
                flagged.add(where)
                break
    for k, v in {**{f"env.{k}": v for k, v in env.items()}, **{f"headers.{k}": v for k, v in headers.items()}}.items():
        key = k.split(".", 1)[1]
        if k in flagged or not CRED_NAME.search(key) or not v.strip():
            continue
        if REFERENCE.match(v) or PLACEHOLDER.search(v):
            continue
        val = v.split(None, 1)[-1] if v.lower().startswith(("bearer ", "token ", "basic ")) else v
        if REFERENCE.match(val):
            continue
        out.append(("credential_in_config", "medium", f"{k} holds a literal value",
                    "keep the value out of the file: reference an env var or the client's secret input"))

    cmd = Path(str(cfg.get("command") or "")).name.lower().removesuffix(".exe").removesuffix(".cmd")
    if cmd in RUNNERS:
        spec, eco = _package_spec(cmd, args)
        if spec:
            state = _pin_state(spec, eco)
            if state == "unpinned":
                out.append(("unpinned_package", "medium", f"{cmd} runs '{spec}' with no fixed version",
                            "pin an exact version (pkg@1.2.3, pkg==1.2.3, image@sha256:...): otherwise every "
                            "launch can fetch new tool code you never reviewed"))
            elif state == "tag":
                out.append(("mutable_image_tag", "low", f"image '{spec}' is pinned by tag, which can be moved",
                            "pin by digest (image@sha256:...) for a version that cannot change"))

    homes = _home_variants()
    broad = [a for a in args if a.rstrip() in homes]
    if broad:
        out.append(("broad_filesystem", "medium", f"server is given '{broad[0]}' as a path",
                    "pass only the folders the task needs; one injected instruction can read anything it can"))

    auto = cfg.get("autoApprove") or cfg.get("alwaysAllow")
    if isinstance(auto, list) and auto:
        names = ", ".join(str(t) for t in auto[:5]) + (" ..." if len(auto) > 5 else "")
        out.append(("auto_approved_tools", "low", f"{len(auto)} tool(s) run without asking: {names}",
                    "keep approval on for any tool that sends data out or changes state"))
    if cfg.get("disabled") is True:
        out = [(k, "low" if s != "high" else s, m + " (server is disabled)", f) for k, s, m, f in out]
    return out


def _display(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        p = str(path)
        home = str(Path.home())
        return "~" + p[len(home):] if p.startswith(home) else p


def audit_file(path: str | Path, client: str | None = None) -> tuple[list[AuditFinding], int, str | None]:
    """(findings, servers checked, parse error or None)."""
    path = Path(path)
    client = client or guess_client(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        return [], 0, f"cannot read: {e.strerror}"
    text = strip_jsonc(raw)
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        return [], 0, f"not valid JSON (line {e.lineno})"
    if not isinstance(doc, dict):
        return [], 0, "top level is not an object"
    found, servers = [], servers_in(doc)
    shown = _display(path)
    lines: dict[tuple[str, str], int] = {}
    for where, name, cfg in servers:
        if where.startswith("projects["):          # same server name can repeat across projects
            anchor = text.find(json.dumps(where[len("projects["):where.index("].")]))
        else:
            anchor = text.find(f'"{where.split(".")[-1]}"')
        line = lines[(where, name)] = _line_of(text, name, max(anchor, 0))
        for kind, sev, msg, fix in check_server(name, cfg):
            found.append(AuditFinding(shown, line, client, name, kind, sev, msg, fix))
    found += _trifecta_findings(servers, lines, shown, client)
    for f in found:
        f.prove = f.prove or proof_for(f.kind, shown)
    return found, len(servers), None


def _trifecta_findings(servers, lines, shown: str, client: str) -> list[AuditFinding]:
    """One agent loads every server in a block (plus the global ones, for a per-project block)."""
    blocks: dict[str, list[tuple[str, dict]]] = {}
    for where, name, cfg in servers:
        blocks.setdefault(where, []).append((name, cfg))
    out = []
    for where, members in blocks.items():
        if where.startswith("projects["):
            members = blocks.get("mcpServers", []) + members
        t = trifecta(members)
        first = min((lines.get((where, n)) or lines.get(("mcpServers", n)) or 1) for n, _ in members)
        for name in t["single"]:
            out.append(AuditFinding(
                shown, lines.get((where, name)) or first, client, name, "lethal_trifecta_in_server", "medium",
                f"{name} alone reads private data, takes in content others write, and can send data out "
                f"({t['kinds'][name]})",
                "use a read-only token or a narrower server, and keep approval on for its outbound tools"))
        if t["across"]:
            legs = t["legs"]
            msg = (f"together these servers give one agent private data ({', '.join(legs['private_read'])}), "
                   f"untrusted content ({', '.join(legs['untrusted_in'])}) and a way out "
                   f"({', '.join(legs['external_out'])}): an instruction planted in the content can move "
                   "the data out")
            names = sorted({n for v in legs.values() for n in v})
            web_only_out = all(t["kinds"][n].startswith("web access") for n in legs["external_out"])
            f = AuditFinding(shown, first, client, ", ".join(names), "lethal_trifecta_across_servers", "medium",
                             msg, "load these in separate clients or profiles, or keep approval on for the "
                                  f"outbound tools of {', '.join(legs['external_out'])}")
            f.prove = proof_for("lethal_trifecta_across_servers/url" if web_only_out
                                else "lethal_trifecta_across_servers", shown)
            out.append(f)
    return out


def audit(paths: list[str] | None = None, project: str | None = ".", user: bool = True) -> dict:
    targets = [(guess_client(Path(p)), Path(p)) for p in paths] if paths else discover(project, user)
    files, findings = [], []
    for client, p in targets:
        f, n, err = audit_file(p, client)
        files.append({"file": _display(p), "client": client, "servers": n, "error": err})
        findings += f
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line, f.kind))
    return {"files": files, "findings": [asdict(f) for f in findings]}


def worst(res: dict) -> int:
    return max((SEVERITY_ORDER[f["severity"]] for f in res["findings"]), default=0)


def format_audit(res: dict, color: bool | None = None) -> str:
    color = sys.stdout.isatty() if color is None else color
    paint = {"high": "1;31", "medium": "1;33", "low": "2"}

    def c(sev, t):
        return f"\033[{paint[sev]}m{t}\033[0m" if color else t

    lines = []
    if not res["files"]:
        return "no MCP client configs found (pass paths explicitly, or --project DIR)"
    for f in res["files"]:
        status = f["error"] or f"{f['servers']} server(s)"
        lines.append(f"  {f['client']:<15} {f['file']}  [{status}]")
    lines.insert(0, f"checked {len(res['files'])} config file(s):")
    if not res["findings"]:
        lines.append("\nno findings.")
        return "\n".join(lines)
    lines.append("")
    for f in res["findings"]:
        lines.append(f"{c(f['severity'], f['severity'].upper()):<8} {f['file']}:{f['line']}  "
                     f"[{f['server']}] {f['message']}")
        lines.append(f"         fix: {f['fix']}")
        if f.get("prove"):
            lines.append(f"         prove: {f['prove']['command']}  ({f['prove']['why']})")
    counts = {s: sum(f["severity"] == s for f in res["findings"]) for s in ("high", "medium", "low")}
    lines.append(f"\n{len(res['findings'])} finding(s): {counts['high']} high, {counts['medium']} medium, "
                 f"{counts['low']} low. Secret values are never printed.")
    return "\n".join(lines)
