# Releasing Taintline

## The name

The project was renamed twice before any release:
- **Tripwire** (until 2026-11-17): an established security product and company (file-integrity
  monitoring, now part of Fortra), in the same field.
- **Dyepack** (2026-11-17 to 2026-11-18): DYEPACK is a known malware family attributed to
  North Korea's APT38, and a crypto-security project already used the name.
- **Taintline** (since 2026-11-18): from taint tracking, which follows untrusted data from its
  source to a sink. That is what this tool proves for AI agents.

Checked 2026-11-18:
- **PyPI:** `taintline` returns 404 (free). Registering it is the real check.
- **GitHub:** no `taintline` user or organization.
- **Domains:** `taintline.com` and `taintline.dev` have no DNS records, so they're probably
  unregistered. Buying one is the real check.
- **Web:** a search found no product, company or malware named Taintline.
- **Still to do before publishing:** a USPTO trademark search (classes 9 and 42).
- **Homebrew:** a tap (`deep60/homebrew-tap`) avoids name questions in core.
- **GitHub repository:** rename it from `dyepack` to `taintline` (Settings > General). GitHub
  redirects the old URL, but the action's `uses:` line, the GHCR image and PyPI trusted
  publishing all use the new name.

## Install paths after release

| path | command | notes |
|---|---|---|
| uv | `uv tool install taintline` | recommended |
| pipx | `pipx install taintline` | |
| pip | `pip install taintline` | in a virtualenv |
| Docker | `docker run --rm --network none ghcr.io/deep60/taintline` | the demo, no setup |
| Homebrew | `brew install deep60/tap/taintline` | after the tap exists, see below |

The wheel bundles the lab servers (`taintline/_lab`), so `taintline demo` and `--lab` work without
a checkout. The release workflow checks this by installing the wheel in a clean environment and
running the demo.

## One-time setup

1. **PyPI trusted publishing:** on pypi.org, under Your account > Publishing > Add a pending
   publisher, enter: owner `deep60`, repo `taintline`, workflow `release.yml`, environment `pypi`.
   No API token is stored anywhere.
2. **GitHub environment:** Settings > Environments > New environment `pypi`. Add yourself as a
   required reviewer, so a tag can't publish without your click.
3. **GHCR:** the workflow pushes `ghcr.io/deep60/taintline` with the built-in token. After the first
   push, set the package's visibility to public.

## Each release

1. Update `__version__` in `src/taintline/__init__.py` and the `CHANGELOG.md` heading
   (`## [X.Y.Z] - YYYY-MM-DD`).
2. Run locally:
   ```bash
   uv run ruff check src tests scripts && uv run python -m pytest -q
   uv build && uv run --isolated --with dist/*.whl taintline demo --out /tmp/tw-demo
   ```
3. Commit, then tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. `release.yml` tests, checks the tag against the version, builds, smoke-tests the wheel, waits
   for your approval on the `pypi` environment, publishes, creates the GitHub release with the
   changelog section, and pushes the Docker image.
5. Homebrew (optional): update `packaging/homebrew/taintline.rb` as its header describes, and copy
   it to the tap repository.

## Status

`release.yml`, the action and the self-test workflow haven't run on GitHub yet. The wheel build,
the clean-install demo, the tag check and the changelog extraction have been run locally.
