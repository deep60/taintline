import json

from tripwire.cli import main


def test_run_writes_report_with_all_trials(tmp_path):
    main(["run", "--agent", "mock-naive", "-n", "2", "--out", str(tmp_path)])
    data = json.loads((tmp_path / "results.json").read_text())
    assert data["summary"]["errors"] == 0 and (tmp_path / "report.md").exists()
    assert all(len(p["trials"]) == 2 for p in data["pairs"])


def test_mutators_add_variants(tmp_path):
    main(["run", "--agent", "mock-hardened", "-n", "1", "--out", str(tmp_path), "--mutators", "base64"])
    ids = {p["attack"] for p in json.loads((tmp_path / "results.json").read_text())["pairs"]}
    assert any(i.endswith("+base64") for i in ids)


def test_pin_then_diff(tmp_path, capsys):
    import pytest
    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps([{"name": "a", "description": "one"}]))
    pins = tmp_path / "pins.json"
    main(["pin", str(manifest), "--out", str(pins)])
    manifest.write_text(json.dumps([{"name": "a", "description": "two"}]))
    with pytest.raises(SystemExit) as e:
        main(["diff", str(pins), str(manifest)])
    assert e.value.code == 1