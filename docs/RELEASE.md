# Releasing Dyepack

## The name

The project was called Tripwire until 2026-11-17. It was renamed before any release, because
"Tripwire" is an established security product and company (file-integrity monitoring, now part
of Fortra), in the same field.

- **PyPI:** `dyepack` is free (checked 2026-11-17: the PyPI JSON API returns 404). A 404 doesn't
  guarantee PyPI will accept the name. Registering it is the real check.
- **Homebrew:** a tap (`deep60/homebrew-tap`) avoids name questions in core.
- **Still to check before publishing:** a trademark search for "Dyepack" in software and security
  (USPTO classes 9 and 42), the GitHub repository name, and a domain.
- **GitHub:** rename the repository from `tripwire` to `dyepack` (Settings > General). GitHub
  redirects the old URL, but the action's `uses:` line, the GHCR image and PyPI trusted
  publishing all use the new name.

## Install paths after release

| path | command | notes |
|---|---|---|
| uv | `uv tool install dyepack` | recommended |
| pipx | `pipx install dyepack` | |
| pip | `pip install dyepack` | in a virtualenv |
| Docker | `docker run --rm --network none ghcr.io/deep60/dyepack` | the demo, no setup |
| Homebrew | `brew install deep60/tap/dyepack` | after the tap exists, see below |

The wheel bundles the lab servers (`dyepack/_lab`), so `dyepack demo` and `--lab` work without
a checkout. The release workflow checks this by installing the wheel in a clean environment and
running the demo.

## One-time setup

1. **PyPI trusted publishing:** on pypi.org, under Your account > Publishing > Add a pending
   publisher, enter: owner `deep60`, repo `dyepack`, workflow `release.yml`, environment `pypi`.
   No API token is stored anywhere.
2. **GitHub environment:** Settings > Environments > New environment `pypi`. Add yourself as a
   required reviewer, so a tag can't publish without your click.
3. **GHCR:** the workflow pushes `ghcr.io/deep60/dyepack` with the built-in token. After the first
   push, set the package's visibility to public.

## Each release

1. Update `__version__` in `src/dyepack/__init__.py` and the `CHANGELOG.md` heading
   (`## [X.Y.Z] - YYYY-MM-DD`).
2. Run locally:
   ```bash
   uv run ruff check src tests scripts && uv run python -m pytest -q
   uv build && uv run --isolated --with dist/*.whl dyepack demo --out /tmp/tw-demo
   ```
3. Commit, then tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. `release.yml` tests, checks the tag against the version, builds, smoke-tests the wheel, waits
   for your approval on the `pypi` environment, publishes, creates the GitHub release with the
   changelog section, and pushes the Docker image.
5. Homebrew (optional): update `packaging/homebrew/dyepack.rb` as its header describes, and copy
   it to the tap repository.

## Status

`release.yml`, the action and the self-test workflow haven't run on GitHub yet. The wheel build,
the clean-install demo, the tag check and the changelog extraction have been run locally.
