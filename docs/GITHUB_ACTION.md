# Tripwire in GitHub: config audit and rug-pull monitor

> **Status:** the commands below are tested locally. The action has **not run on GitHub yet**.
> `.github/workflows/action-selftest.yml` will run it once this repo is pushed.

## 1. Audit MCP configs on every pull request

`tripwire audit` reads MCP client configs and checks every server entry. It starts nothing and
needs no scope file:

| finding | severity | what it means |
|---|---|---|
| `secret_in_config` | high | a token-shaped value in args, env, headers or the URL (never printed) |
| `insecure_transport` | high | a remote server reached over plain `http` |
| `credential_in_config` | medium | an env var named like a credential holds a literal value, not `${env:X}` |
| `unpinned_package` | medium | `npx`/`uvx`/`pipx`/`bunx`/`docker` fetches a server with no fixed version |
| `broad_filesystem` | medium | a server is handed `/` or the home folder |
| `mutable_image_tag` | low | a docker image pinned by tag rather than digest |
| `auto_approved_tools` | low | tools set to run without asking the user |

Why `unpinned_package` matters: `npx -y some-mcp-server` downloads whatever the latest version is
at every launch. A new release can change tool descriptions, which is a rug pull at the package
level, and nobody reviews it.

On your machine, with no arguments, it finds the per-user configs (Claude Desktop, Claude Code,
Cursor, VS Code, Windsurf) and the project files in the current folder:

```bash
tripwire audit
tripwire audit --no-user --sarif tripwire.sarif   # project files only, as CI does
```

In a repository, copy [examples/workflows/tripwire-audit.yml](../examples/workflows/tripwire-audit.yml)
to `.github/workflows/`. Findings show up in the code scanning tab and on the pull request, **on the
config file's own line**.

```yaml
- uses: actions/checkout@v4
- uses: deep60/tripwire@main      # pin a tag or SHA once released
  with:
    fail-on: high                 # high | medium | low | never
```

## 2. Watch servers for rug pulls on a schedule

`tripwire monitor --config .mcp.json` starts each server in the config, lists its tools, and
compares them with one pin file per server:

```bash
tripwire monitor --config .mcp.json --pins-dir .tripwire/pins            # first run: writes baselines
tripwire monitor --config .mcp.json --pins-dir .tripwire/pins            # later: OK / DRIFT / UNCHECKED
tripwire monitor --config .mcp.json --pins-dir .tripwire/pins --update   # accept a change you reviewed
```

- Every server must be listed in `SCOPE.yaml`. Monitoring **starts** stdio servers and contacts
  URL servers, so a server outside the scope is refused before anything runs.
- `${env:VAR}`, `${VAR}` and `$VAR` in args and env come from the environment, and
  `${workspaceFolder}` becomes the project folder. A missing variable makes that server
  `UNCHECKED`.
- **`UNCHECKED` is never a pass.** This covers a server outside the scope, a missing env var, a
  timeout, or a URL server that needs custom headers (not supported yet).
- `--notify-url` sends a signed webhook on drift, as plain `monitor` does.

For a daily job, use [examples/workflows/tripwire-monitor.yml](../examples/workflows/tripwire-monitor.yml).
Commit `SCOPE.yaml` and the reviewed `.tripwire/pins/` first.

## Exit codes

| command | 0 | 1 | 3 |
|---|---|---|---|
| `audit` | nothing at or above `--fail-on` | a finding at or above `--fail-on` | a config file could not be parsed |
| `monitor --config` | every server checked and unchanged (or baselined) | drift on any server | a server could not be checked |

The action exposes this as the `exit-code` output and fails the job on 1 or 3.

## Action inputs

| input | default | used by |
|---|---|---|
| `command` | `audit` | `audit` or `monitor` |
| `paths` | (discover) | audit: files to check, space separated |
| `fail-on` | `high` | audit |
| `config` | `.mcp.json` | monitor |
| `pins-dir` | `.tripwire/pins` | monitor |
| `scope` | `SCOPE.yaml` | monitor |
| `sarif-file` | `tripwire.sarif` | both |
| `upload-sarif` | `true` | both (needs `security-events: write`) |

## Limits

- Config locations change between client releases. Discovery uses a best-known list, so pass paths
  explicitly if a file is missed.
- The audit is static. It can't see tool names that collide across servers, because that needs the
  servers running. `monitor` lists the tools.
- Secret detection is pattern-based. It catches common token formats and credential-named env vars
  with literal values, not every secret.
