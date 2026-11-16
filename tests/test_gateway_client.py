import json
import sys
from pathlib import Path

import pytest

from dyepack.cli import main
from dyepack.gateway.hash import hash_tools
from dyepack.scanner.enumerate import enumerate_server
from dyepack.scope import Gate, OutOfScope, parse_scope

SERVER = str(Path(__file__).parent.parent / "lab" / "servers" / "notes_server.py")


def _gate(*servers):
    return Gate(parse_scope({"name": "t", "authorized_by": "me", "servers": list(servers)}))


def test_enumerate_lists_tools():
    tools = enumerate_server(_gate("notes"), "notes", sys.executable, [SERVER])
    assert {t["name"] for t in tools} == {"read_note", "send_email"}
    assert all("inputSchema" in t for t in tools)
    assert len(hash_tools(tools)) == 2


def test_out_of_scope_refused_before_spawning():
    with pytest.raises(OutOfScope):
        enumerate_server(_gate("other"), "notes", "definitely-not-a-real-command", [])


def test_server_that_never_answers_times_out():
    with pytest.raises(TimeoutError):
        enumerate_server(_gate("notes"), "notes", sys.executable, ["-c", "import time; time.sleep(60)"],
                         timeout=2)


def test_cli_enumerate_json(tmp_path, capsys):
    sc = tmp_path / "s.yaml"
    sc.write_text("name: t\nauthorized_by: me\nservers: [notes]\n")
    main(["enumerate", "--server", "notes", "--command", sys.executable, "--arg", SERVER,
          "--scope", str(sc), "--json"])
    assert {t["name"] for t in json.loads(capsys.readouterr().out)} == {"read_note", "send_email"}


def test_cli_enumerate_refuses_without_scope(tmp_path):
    with pytest.raises(SystemExit) as e:
        main(["enumerate", "--server", "notes", "--command", "x", "--scope", str(tmp_path / "no.yaml")])
    assert "refused" in str(e.value)


def test_cli_enumerate_refuses_unlisted_server(tmp_path):
    sc = tmp_path / "s.yaml"
    sc.write_text("name: t\nauthorized_by: me\nservers: [other]\n")
    with pytest.raises(SystemExit) as e:
        main(["enumerate", "--server", "notes", "--command", "x", "--scope", str(sc)])
    assert "not in scope" in str(e.value)
