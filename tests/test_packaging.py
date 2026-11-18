import tomllib
from pathlib import Path

import pytest

import taintline
from taintline.cli import main
from taintline.paths import lab_dir

ROOT = Path(__file__).resolve().parents[1]


def test_lab_dir_has_every_lab_server():
    from taintline.labs import LABS
    servers = lab_dir() / "servers"
    for lab in LABS.values():
        for name in lab.servers:
            assert (servers / f"{name}_server.py").is_file(), name
    assert (lab_dir() / "collaborator" / "server.py").is_file()


def test_wheel_bundles_what_lab_dir_needs():
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text())
    forced = cfg["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    assert forced["lab/servers"] == "taintline/_lab/servers"
    assert forced["lab/collaborator/server.py"] == "taintline/_lab/collaborator/server.py"
    assert cfg["project"]["dynamic"] == ["version"]


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0 and capsys.readouterr().out.strip() == f"taintline {taintline.__version__}"


def test_changelog_has_a_section_for_this_version():
    assert f"## [{taintline.__version__}]" in (ROOT / "CHANGELOG.md").read_text()
