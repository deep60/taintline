from __future__ import annotations

import json
import os

from .schema import stamp


def write_json(result: dict, summary: dict, out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = f"{out_dir}/results.json"
    with open(path, "w") as f:
        json.dump(stamp({"summary": summary, **result}, "run"), f, indent=2)
    return path
