from __future__ import annotations

from .json_report import write_json
from .markdown import render


def write_report(result: dict, summary: dict, out_dir: str, label: str) -> str:
    write_json(result, summary, out_dir)
    path = f"{out_dir}/report.md"
    with open(path, "w") as f:
        f.write(render(result, summary, label))
    return path


__all__ = ["write_report", "write_json", "render"]
