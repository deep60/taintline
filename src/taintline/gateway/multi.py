"""Several real stdio MCP servers behind one Sandbox look-alike, so a lab can model what real
agents have: a tool that reads private data on one server and a tool that sends it out on another.

Each server runs behind its own recording proxy. An injection goes to the server named in
inject["server"] (default: the first). If two servers expose the same tool name, the later one
wins, which is how a malicious server shadows a legitimate tool; shadowed names are listed in
`self.shadowed`.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..sandbox import ToolCall
from ..scope import Gate
from .mcp_sandbox import MCPSandbox


@dataclass
class ServerSpec:
    name: str                 # scope-gate name
    command: str
    args: list[str] = field(default_factory=list)


class MultiSandbox:
    def __init__(self, gate: Gate, specs: list[ServerSpec], canaries: dict | None = None,
                 env: dict | None = None, inject: dict | None = None,
                 transcript_prefix: str | None = None, timeout: float = 30.0):
        if not specs:
            raise ValueError("MultiSandbox needs at least one server")
        for s in specs:                       # every server is a network target: gate all first
            gate.check_server(s.name)
        target = (inject or {}).get("server") or specs[0].name
        if inject and target not in {s.name for s in specs}:
            raise ValueError(f"injection targets server '{target}' which is not in this lab")
        self.canaries = dict(canaries or {})
        self.injection = inject
        self.calls: list[ToolCall] = []
        self.shadowed: list[str] = []
        self.transcripts: list[str] = []
        self._boxes: list[MCPSandbox] = []
        self._route: dict[str, MCPSandbox] = {}
        for s in specs:
            t = f"{transcript_prefix}.{s.name}.jsonl" if transcript_prefix else None
            if t:
                self.transcripts.append(t)
            self._boxes.append(MCPSandbox(gate, s.name, s.command, s.args, self.canaries, env,
                                          inject if s.name == target else None, t, timeout))

    def start(self) -> "MultiSandbox":
        try:
            for b in self._boxes:
                b.start()
        except BaseException:
            self.close()
            raise
        return self

    def close(self) -> None:
        for b in self._boxes:
            b.close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.close()

    def tool_defs(self) -> list[dict]:
        defs: dict[str, dict] = {}
        self._route, self.shadowed = {}, []
        for b in self._boxes:
            for d in b.tool_defs():
                if d["name"] in defs:
                    self.shadowed.append(d["name"])
                defs[d["name"]] = d
                self._route[d["name"]] = b
        return list(defs.values())

    def call(self, name: str, args: dict) -> str:
        if not self._route:
            self.tool_defs()
        box = self._route.get(name)
        if box is None:
            result = f"error: unknown tool {name}"
            self.calls.append(ToolCall(name, dict(args or {}), result))
            return result
        result = box.call(name, args)
        self.calls.append(box.calls[-1])
        return result
