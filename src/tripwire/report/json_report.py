from __future__ import annotations

import json
import os


def write_json(result: dict, summary: dict, out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = f"{out_dir}/results.json"
    with open(path, "w") as f:
        json.dump({"summary": summary, **result}, f, indent=2)
    return path
