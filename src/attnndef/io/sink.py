"""Local append-only evidence sink (JSON Lines).

Deliberately local-only: one file, one process-wide lock. No network I/O,
no external service. Good enough for a single laptop running fixtures;
NOT designed for multi-host coordination (see README UNKNOWN).
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Callable, Iterator, Optional

from ..core.models import Evidence


class LocalSink:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, evidence: Evidence) -> None:
        line = json.dumps(evidence.to_json_dict(), separators=(",", ":"))
        with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self._lock:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        return [json.loads(l) for l in lines if l.strip()]

    def filter(self, predicate: Callable[[dict], bool]) -> Iterator[dict]:
        for row in self.read_all():
            if predicate(row):
                yield row

    def by_kind(self, kind: str) -> list[dict]:
        return list(self.filter(lambda r: r.get("kind") == kind))

    def by_target(self, target_id: str) -> list[dict]:
        return list(self.filter(lambda r: r.get("target_id") == target_id))
