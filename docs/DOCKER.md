# Running Tripwire in Docker

You need Docker Desktop (or any Docker engine) running. Nothing else: Python, uv and the lab
servers are all inside the image.

## 1. Build the image (once, about 1-2 minutes)
```bash
docker build -t tripwire .
```
The first build downloads the `python:3.12-slim` base image and the pinned `uv` binary.

## 2. Watch the demo (no network, no model, no API key)
```bash
docker run --rm --network none tripwire
```
Three scenes run against the real `notes` MCP server inside the container:
1. **Baseline:** a normal task. The sink stays empty.
2. **Attack:** an instruction injected into a tool result makes the agent email the secret.
   The sink receives the canary, which proves the leak.
3. **Defended:** the same attack against an agent that treats tool output as data. Nothing leaks.

`--network none` is the point: the container has no network at all, and the leak is still proven,
because the "attacker" sink runs on the container's own loopback. The agents in this mode are
scripted stand-ins, not models.

To keep the results file, mount a folder:
```bash
docker run --rm --network none -v "$PWD/out:/app/out" tripwire
```
It writes `out/demo/demo.json` and `out/demo/replay.html`. Open the replay in a browser to step
through each scene: where the injected text came in, and where the secret left. Or use compose, which adds a read-only filesystem and drops all capabilities:
```bash
docker compose run --rm demo
```

## 3. Put a real model in the attack scene
The container reaches a model on your Mac at `host.docker.internal`.

1. Make the model server listen beyond 127.0.0.1:
   - **LM Studio:** Developer tab, turn on **Serve on Local Network**, then start the server (port 1234).
   - **Ollama:** quit it, then start it with `OLLAMA_HOST=0.0.0.0 ollama serve` (port 11434).
2. Authorize the host in your `SCOPE.yaml`. A real model is a network target, so the scope gate applies:
   ```yaml
   servers:
     - host.docker.internal:1234
   ```
3. Run it, mounting the scope file read-only:
   ```bash
   docker run --rm -v "$PWD/SCOPE.yaml:/app/SCOPE.yaml:ro" -v "$PWD/out:/app/out" tripwire \
     demo --agent openai-compat --model YOUR_MODEL_ID --base-url http://host.docker.internal:1234/v1
   ```
   For Ollama, use `--agent ollama --base-url http://host.docker.internal:11434` instead.

One trial is a demo, not a measurement. For rates with confidence intervals, run `live-suite`.

## 4. Any other command
The image's entrypoint is `tripwire`, so any subcommand works:
```bash
docker run --rm tripwire labs
docker run --rm tripwire --help
```

## Exit codes
- `0`: the demo ran cleanly.
- `2`: a scene errored, or the baseline raised a false alarm. Errors never count as "secure".
