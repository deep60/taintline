"""`tripwire monitor --config FILE`: rug-pull check for every server in an MCP client config.

For each server: start it (stdio) or call it (HTTP), list its tools, and compare against its pin file in
`pins_dir`. The first run writes the baselines. Every server must be authorized in SCOPE.yaml, because
listing tools means starting the server or contacting its host.

A server that could not be checked (out of scope, a missing env var, a timeout, an HTTP server that needs
headers) is reported as `unchecked`, never as `ok`: no answer is not the same as no drift."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from ..scope import OutOfScope
from .config_audit import servers_in, strip_jsonc
from .enumerate import enumerate_server, enumerate_url
from .rugpull import check, pin

VAR = re.compile(r"\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")


class MissingEnv(Exception):
    pass


def resolve(value: str, root: Path) -> str:
    """Expand ${VAR}, ${env:VAR} and $VAR from the environment; ${workspaceFolder} to the project root."""
    value = value.replace("${workspaceFolder}", str(root))

    def sub(m):
        name = m.group(1) or m.group(2)
        if name not in os.environ:
            raise MissingEnv(name)
        return os.environ[name]
    return VAR.sub(sub, value)


def _project_root(config: Path) -> Path:
    p = config.resolve().parent
    return p.parent if p.name in (".vscode", ".cursor") else p


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name) or "server"


def monitor_config(gate, config: str | Path, pins_dir: str | Path, timeout: float = 30.0,
                   update: bool = False, list_stdio=enumerate_server, list_url=enumerate_url) -> dict:
    config, pins_dir = Path(config), Path(pins_dir)
    doc = json.loads(strip_jsonc(config.read_text(encoding="utf-8")))
    root = _project_root(config)
    pins_dir.mkdir(parents=True, exist_ok=True)
    out = []
    for _, name, cfg in servers_in(doc):
        row = {"server": name, "status": "", "detail": "", "report": None}
        out.append(row)
        if cfg.get("disabled") is True:
            row.update(status="skipped", detail="disabled in the config")
            continue
        try:
            url = cfg.get("url") or cfg.get("serverUrl")
            if url:
                if cfg.get("headers"):
                    raise RuntimeError("needs custom headers, which monitor does not send yet")
                tools = list_url(gate, resolve(url, root), timeout)
            elif cfg.get("command"):
                env = {k: resolve(v, root) for k, v in (cfg.get("env") or {}).items() if isinstance(v, str)}
                args = [resolve(a, root) for a in (cfg.get("args") or []) if isinstance(a, str)]
                tools = list_stdio(gate, name, resolve(cfg["command"], root), args, timeout, env or None)
            else:
                raise RuntimeError("no command or url")
        except OutOfScope as e:
            row.update(status="unchecked", detail=f"refused by scope: {e}")
            continue
        except MissingEnv as e:
            row.update(status="unchecked", detail=f"env var {e} is not set")
            continue
        except TimeoutError:
            row.update(status="unchecked", detail=f"no answer within {timeout}s")
            continue
        except Exception as e:                     # noqa: BLE001 - any failure is reported, never passed
            row.update(status="unchecked", detail=f"{type(e).__name__}: {str(e)[:200]}")
            continue
        path = pins_dir / f"{_safe(name)}.json"
        if not path.exists() or update:
            path.write_text(json.dumps(pin(tools), indent=2) + "\n")
            row.update(status="baseline", detail=f"{len(tools)} tools pinned -> {path}")
            continue
        report = check(json.loads(path.read_text()), tools)
        row["report"] = report
        if report["changes"]:
            row.update(status="drift", detail=f"{len(report['changes'])} tool(s) changed since pinned")
        else:
            row.update(status="ok", detail=f"{len(tools)} tools match")
    return {"config": str(config), "pins_dir": str(pins_dir), "servers": out}


def exit_code(res: dict) -> int:
    st = [s["status"] for s in res["servers"]]
    return 1 if "drift" in st else 3 if "unchecked" in st else 0
