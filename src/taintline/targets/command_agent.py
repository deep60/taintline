"""Bring your own agent: run the agent under test as its own process, once per trial.

Taintline starts a local MCP endpoint (gateway/bridge.py) backed by the trial's sandbox, then runs
your command with:

    stdin / TAINTLINE_PROMPT   the task prompt
    TAINTLINE_MCP_URL          Streamable HTTP MCP endpoint with the lab's tools (127.0.0.1 only)
    TAINTLINE_MCP_CONFIG       path to an `mcpServers` JSON config for agents that launch stdio servers
    TAINTLINE_MCP_STDIO        the same stdio command, as a JSON list
    TAINTLINE_SYSTEM           a system prompt override (set by --system or --gullible), if any
    TAINTLINE_MODEL, TAINTLINE_SEED       --model and the trial seed, for agents that want them
    TAINTLINE_BASE_URL         --base-url (the model API the scope gate checked), if given
    TAINTLINE_USAGE_FILE       optional: write {"tokens": N} here so --max-tokens can count usage

Your agent prints its final answer on stdout and exits 0. Exit 4 means "gave up at my turn limit"
(reported like the built-in agents' turn limit); any other non-zero exit, or running past the
timeout, is counted as an error, never as secure. The canary secrets live only in the lab
servers' environment; they are never put in the agent's.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

from ..gateway.bridge import McpBridge
from .own_agent import AgentTimeout

EXIT_TURN_LIMIT = 4
DEFAULT_TIMEOUT = 600.0
_STDERR_TAIL = 800


def reason(stderr: str) -> str:
    """The line that says why the agent failed: the last one with text in it. Python prints the
    exception last, but exception groups wrap it in `|` and `+---` borders, which are skipped."""
    for line in reversed(stderr.splitlines()):
        text = line.strip().strip("|+-").strip()
        if any(c.isalnum() for c in text):
            return text
    return ""


class CommandAgent:
    def __init__(self, command: list[str], seed: int = 0, system: str | None = None,
                 model: str | None = None, timeout: float | None = None, cwd: str | None = None,
                 base_url: str | None = None):
        if not command:
            raise ValueError("command agent needs a command")
        self.command = list(command)
        self.seed, self.system, self.model, self.cwd = seed, system, model, cwd
        self.base_url = base_url
        self.timeout = timeout or DEFAULT_TIMEOUT
        self.tokens_used = 0

    def _env(self, prompt: str, br: McpBridge, config: Path, usage: Path) -> dict:
        env = {**os.environ,
               "TAINTLINE_PROMPT": prompt, "TAINTLINE_MCP_URL": br.url,
               "TAINTLINE_MCP_CONFIG": str(config), "TAINTLINE_MCP_STDIO": json.dumps(br.stdio_command),
               "TAINTLINE_SEED": str(self.seed), "TAINTLINE_USAGE_FILE": str(usage)}
        for key, val in (("TAINTLINE_SYSTEM", self.system), ("TAINTLINE_MODEL", self.model),
                         ("TAINTLINE_BASE_URL", self.base_url)):
            if val:
                env[key] = val
            else:
                env.pop(key, None)
        return env

    def run(self, prompt: str, sb) -> str:
        with McpBridge(sb) as br, tempfile.TemporaryDirectory(prefix="taintline-agent-") as tmp:
            config = Path(tmp, "mcp.json")
            config.write_text(json.dumps({"mcpServers": {"taintline": {
                "command": br.stdio_command[0], "args": br.stdio_command[1:]}}}, indent=2))
            usage = Path(tmp, "usage.json")
            try:
                p = subprocess.run(self.command, input=prompt, capture_output=True, text=True,
                                   timeout=self.timeout, cwd=self.cwd,
                                   env=self._env(prompt, br, config, usage))
            except subprocess.TimeoutExpired:
                raise RuntimeError(f"agent command timed out after {self.timeout:g}s") from None
            self._read_usage(usage)
        if p.returncode == EXIT_TURN_LIMIT:
            raise AgentTimeout(p.stdout.strip() or "agent command reported its turn limit (exit 4)")
        if p.returncode != 0:
            err = (p.stderr or "").strip()
            last = reason(err)
            msg = f"agent command exited {p.returncode}" + (f": {last}" if last else "")
            raise RuntimeError(msg + (f"\n{err[-_STDERR_TAIL:]}" if err and err != last else ""))
        return p.stdout.strip()

    def _read_usage(self, usage: Path) -> None:
        try:
            self.tokens_used += int(json.loads(usage.read_text()).get("tokens", 0))
        except (OSError, ValueError, AttributeError, TypeError):
            pass
