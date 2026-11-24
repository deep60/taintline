"""A minimal agent you can point Taintline at, or copy into your own agent's test harness.

It connects to the tools Taintline gives it over MCP (TAINTLINE_MCP_URL), and runs a plain tool-use
loop against any OpenAI-compatible chat API (Ollama, LM Studio, vLLM, OpenAI):

    taintline live-suite --lab notes --agent command \\
        --agent-cmd "python examples/byo_agent/agent.py" --model llama3.1:latest

Model endpoint: OPENAI_BASE_URL (default http://localhost:11434/v1, Ollama) and OPENAI_API_KEY.
Your real agent only has to follow the same contract: prompt on stdin, tools over MCP, answer on
stdout, exit 0 (or 4 when it gives up at its turn limit). See docs/BYO_AGENT.md.
"""
import asyncio
import json
import os
import sys

import httpx
from mcp import Client

BASE_URL = os.environ.get("OPENAI_BASE_URL", "http://localhost:11434/v1").rstrip("/")
MODEL = os.environ.get("TAINTLINE_MODEL") or os.environ.get("AGENT_MODEL", "llama3.1:latest")
SYSTEM = os.environ.get("TAINTLINE_SYSTEM") or "You are a helpful assistant with tool access."
MAX_TURNS = 8
EXIT_TURN_LIMIT = 4


async def main() -> int:
    prompt = sys.stdin.read()
    tokens = 0
    async with Client(os.environ["TAINTLINE_MCP_URL"]) as mcp:
        tools = [{"type": "function", "function": {"name": t.name, "description": t.description or "",
                                                   "parameters": t.input_schema}}
                 for t in (await mcp.list_tools()).tools]
        msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}]
        headers = {"Authorization": f"Bearer {os.environ.get('OPENAI_API_KEY', 'none')}"}
        async with httpx.AsyncClient(timeout=300) as http:
            for _ in range(MAX_TURNS):
                r = await http.post(f"{BASE_URL}/chat/completions", headers=headers,
                                    json={"model": MODEL, "messages": msgs, "tools": tools})
                r.raise_for_status()
                body = r.json()
                tokens += (body.get("usage") or {}).get("total_tokens", 0)
                msg = body["choices"][0]["message"]
                msgs.append(msg)
                calls = msg.get("tool_calls") or []
                if not calls:
                    print(msg.get("content") or "")
                    break
                for c in calls:
                    fn = c["function"]
                    args = fn.get("arguments") or "{}"
                    res = await mcp.call_tool(fn["name"], json.loads(args) if isinstance(args, str) else args)
                    text = "".join(getattr(x, "text", "") for x in res.content)
                    msgs.append({"role": "tool", "tool_call_id": c.get("id", ""), "content": text})
            else:
                print(f"no final answer after {MAX_TURNS} turns")
                return EXIT_TURN_LIMIT
    usage = os.environ.get("TAINTLINE_USAGE_FILE")
    if usage:
        with open(usage, "w") as f:
            json.dump({"tokens": tokens}, f)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
