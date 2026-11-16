import pytest

from dyepack.cli import main

SCOPE = """name: t
authorized_by: me
servers:
  - localhost:11434
"""


def test_hermetic_agent_needs_no_scope(tmp_path):
    main(["run", "--agent", "mock-naive", "--dry-run", "--scope", str(tmp_path / "none.yaml")])


def test_network_agent_refused_without_scope(tmp_path):
    with pytest.raises(SystemExit) as e:
        main(["run", "--agent", "ollama", "--model", "x", "--scope", str(tmp_path / "none.yaml"), "--dry-run"])
    assert "refused" in str(e.value)


def test_network_agent_allowed_when_in_scope(tmp_path, capsys):
    sc = tmp_path / "s.yaml"
    sc.write_text(SCOPE)
    main(["run", "--agent", "ollama", "--model", "x", "--scope", str(sc), "--dry-run"])
    assert "no calls made" in capsys.readouterr().out


def test_out_of_scope_host_refused(tmp_path):
    sc = tmp_path / "s.yaml"
    sc.write_text(SCOPE)
    with pytest.raises(SystemExit) as e:
        main(["run", "--agent", "openai-compat", "--model", "m", "--base-url", "https://api.other.com/v1",
              "--scope", str(sc), "--dry-run"])
    assert "not in scope" in str(e.value)


def test_invalid_scope_rejected(tmp_path):
    sc = tmp_path / "s.yaml"
    sc.write_text("name: t\n")
    with pytest.raises(SystemExit):
        main(["run", "--agent", "ollama", "--model", "x", "--scope", str(sc), "--dry-run"])
