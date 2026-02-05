from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

class JsonlBuffer:
    """Local buffer for unsent messages (JSON Lines)."""

    def __init__(self, dir_path: str):
        self.dir = Path(dir_path)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "unsent.jsonl"

    def append(self, obj: dict) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    def drain(self, limit: int = 500) -> list[dict]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        take = lines[:limit]
        rest = lines[limit:]
        if rest:
            self.path.write_text("\n".join(rest) + "\n", encoding="utf-8")
        else:
            self.path.unlink(missing_ok=True)
        out: list[dict] = []
        for ln in take:
            try:
                out.append(json.loads(ln))
            except Exception:
                continue
        return out
