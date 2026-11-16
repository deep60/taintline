"""Where the bundled lab servers live.

From a source checkout (and the Docker image, which installs the checkout) they are in `<repo>/lab`.
A wheel from PyPI carries a copy inside the package at `dyepack/_lab` (see pyproject.toml), so
`pip install dyepack && dyepack demo` works with no checkout."""
from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).resolve().parent


def lab_dir() -> Path:
    packaged = _HERE / "_lab"
    if (packaged / "servers").is_dir():
        return packaged
    return _HERE.parents[1] / "lab"
