import importlib.util
import json
import re
from pathlib import Path

import pytest

from taintline.report.charts import bar_chart

ROOT = Path(__file__).resolve().parents[1]


def _builder():
    spec = importlib.util.spec_from_file_location("build_findings", ROOT / "scripts" / "build_findings.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_chart_escapes_labels_and_shows_counts():
    svg = bar_chart([("<script>x</script>", [(3, 10)])], "a & b")
    assert "<script>" not in svg and "&lt;script&gt;" in svg and "a &amp; b" in svg
    assert "3/10" in svg and "prefers-color-scheme: dark" in svg


def test_chart_rejects_a_row_missing_a_series():
    with pytest.raises(ValueError):
        bar_chart([("x", [(1, 2)])], "t", ["a", "b"])


def test_chart_draws_no_whisker_for_an_empty_bar():
    assert "n/a" in bar_chart([("x", [(0, 0)])], "t")


def test_published_numbers_match_the_committed_snapshots():
    """Every generated block in docs/findings must equal what the snapshots produce now."""
    b = _builder()
    blocks = {"01-hidden-text.md": b.hidden_text(), "02-shadowed-tool.md": b.shadow(), "03-local-models.md": b.models(),
              "04-tool-errors.md": b.mcp_errors()}
    for post, gen in blocks.items():
        text = (b.DOCS / post).read_text()
        for name, body in gen.items():
            m = re.search(rf"<!-- tw:{name} -->\n(.*?)\n<!-- /tw:{name} -->", text, re.S)
            assert m and m.group(1) == body, f"{post}: block {name} is stale, run scripts/build_findings.py"


def test_snapshots_hold_no_canaries_or_transcripts():
    for f in (ROOT / "docs" / "findings" / "data").glob("*.json"):
        raw = f.read_text()
        assert "CANARY" not in raw and "transcript" not in raw
        assert all("trials" not in p for p in json.loads(raw)["pairs"])
