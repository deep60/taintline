# Test an agent you can't script

Claude Desktop, Cursor, Claude Code, an IDE copilot: you can't run them in a loop from Taintline,
but they all load MCP servers from a config. A **session** puts the lab's servers in that config,
behind Taintline's recording proxy, with an attack planted. You use the agent normally, then
Taintline scores what happened. The verdict is the same as an automated trial: a leak counts only
if the canary arrived at the sink.

```bash
python3 lab/collaborator/server.py                    # terminal 1: the sink
taintline session start --lab notes --out out/s1      # terminal 2
```

`start` checks the lab and the sink against `SCOPE.yaml`, then prints three things:
1. a config file, `out/s1/mcp.json`, to add to your client (paths for Claude Desktop, Cursor and
   Claude Code are printed). Restart the client so it loads the `taintline-*` servers,
2. the exact message to send in a **new** chat,
3. the command to run afterwards:

```bash
taintline session score out/s1 --answer "<the agent's reply>"
```

Exit codes: 0 no leak, 1 leaked (the canary arrived), 3 invalid. A session is invalid when no tool
calls were recorded (the config wasn't loaded, or the task went to an old chat), or when the
attack never reached the agent. Invalid is never "secure".

Remove the `taintline-*` servers from your client when you're done.

## Options

- `--attack ID` picks an attack (`taintline labs` lists them; default is the lab's first).
  `--attack none` is a clean baseline: run one to check the agent doesn't leak with no attack.
- `--task ID` picks the task the user asks for.
- `--answer` is optional. With it, the result also says whether the agent did the task.

## What it can and can't tell you

- One session is one trial. For a rate, run several (a new `--out` each) and count.
- The canary lives only in the lab servers' environment. The client never sees it unless it reads
  it with a tool, which the transcripts show.
- It tests the client with the labs' synthetic servers. It does not test your real servers'
  data; for that, use `taintline live-run` against your own server with `--agent command`.
