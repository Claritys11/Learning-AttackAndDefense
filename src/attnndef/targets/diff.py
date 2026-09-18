from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Iterable
from .models import Observation, Service

class DiffKind(str, Enum):
    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"
    STATUS_CHANGED = "status_changed"

@dataclass(frozen=True)
class DiffEntry:
    kind: DiffKind
    identity: tuple[str, int]
    previous: Service | None = None
    current: Service | None = None

    @property
    def label(self) -> str:
        protocol, port = self.identity
        service = self.current or self.previous
        name = service.name if service else "unknown"
        return f"{port}/{protocol} {name}"

@dataclass(frozen=True)
class IntelligenceDiff:
    previous_id: int | None
    current_id: int | None
    entries: tuple[DiffEntry, ...]

    @property
    def added(self): return tuple(x for x in self.entries if x.kind is DiffKind.ADDED)
    @property
    def removed(self): return tuple(x for x in self.entries if x.kind is DiffKind.REMOVED)
    @property
    def changed(self): return tuple(x for x in self.entries if x.kind is DiffKind.CHANGED)
    @property
    def status_changed(self): return tuple(x for x in self.entries if x.kind is DiffKind.STATUS_CHANGED)

    def render(self) -> str:
        lines = []
        for kind, title in ((self.added, "ADDED"), (self.removed, "REMOVED"), (self.changed, "CHANGED"), (self.status_changed, "STATUS_CHANGED")):
            if kind:
                lines.append(f"{title}:")
                for entry in kind:
                    lines.append(f"  {entry.label}")
        return "\n".join(lines) if lines else "No observable changes."

def compare_observations(previous: Observation, current: Observation) -> IntelligenceDiff:
    before = {(s.protocol, s.port): s for s in previous.services}
    after = {(s.protocol, s.port): s for s in current.services}
    entries: list[DiffEntry] = []
    for identity in sorted(after.keys() - before.keys()): entries.append(DiffEntry(DiffKind.ADDED, identity, current=after[identity]))
    for identity in sorted(before.keys() - after.keys()): entries.append(DiffEntry(DiffKind.REMOVED, identity, previous=before[identity]))
    for identity in sorted(before.keys() & after.keys()):
        old, new = before[identity], after[identity]
        if old.status != new.status and old.port == new.port and old.protocol == new.protocol and old.name == new.name and old.version == new.version:
            entries.append(DiffEntry(DiffKind.STATUS_CHANGED, identity, old, new))
        elif old != new:
            entries.append(DiffEntry(DiffKind.CHANGED, identity, old, new))
    return IntelligenceDiff(previous.id, current.id, tuple(entries))

def diff_history(history: Iterable[Observation]) -> IntelligenceDiff | None:
    observations = list(history)
    if len(observations) < 2: return None
    return compare_observations(observations[1], observations[0])
