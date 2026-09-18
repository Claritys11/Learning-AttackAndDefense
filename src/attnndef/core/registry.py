"""Target registry.

Targets are declared in a local JSON file -- there is NO discovery against
a real platform here (see README: GZCTF team/service enumeration is
UNKNOWN and intentionally not implemented). `discover` in the CLI just
means "load + filter this local file".

Expected fixture config schema (config/targets.json):

{
  "targets": [
    {
      "id": "svc-own-01",
      "name": "own-web",
      "host": "127.0.0.1",
      "port": 8001,
      "role": "own",
      "tags": ["web"],
      "metadata": {"config_path": "/path/to/fixture/config.ini"}
    }
  ]
}
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Optional

from .errors import TargetNotFoundError
from .models import Role, Target


class TargetRegistry:
    def __init__(self, targets: Optional[list[Target]] = None) -> None:
        self._by_id: dict[str, Target] = {t.id: t for t in (targets or [])}

    @classmethod
    def from_file(cls, path: str | Path) -> "TargetRegistry":
        data = json.loads(Path(path).read_text())
        records = data if isinstance(data, list) else data.get("targets", [])
        targets = []
        for raw in records:
            targets.append(
                Target(
                    id=raw["id"],
                    name=raw.get("name", raw["id"]),
                    host=raw["host"],
                    port=int(raw["port"]),
                    role=Role(raw.get("role", "unknown")),
                    tags=tuple(raw.get("tags", [])),
                    metadata=raw.get("metadata", {}),
                )
            )
            if targets[-1].host not in {"127.0.0.1", "localhost", "::1"}:
                raise ValueError(f"non-local target rejected: {targets[-1].host}")
        return cls(targets)

    def add(self, target: Target) -> None:
        self._by_id[target.id] = target

    def get(self, target_id: str) -> Target:
        try:
            return self._by_id[target_id]
        except KeyError as exc:
            raise TargetNotFoundError(target_id) from exc

    def all(self) -> list[Target]:
        return list(self._by_id.values())

    def filter(
        self,
        role: Optional[Role] = None,
        tags: Optional[Iterable[str]] = None,
    ) -> list[Target]:
        tags = set(tags or [])
        out = []
        for t in self._by_id.values():
            if role is not None and t.role != role:
                continue
            if tags and not tags.issubset(set(t.tags)):
                continue
            out.append(t)
        return out
