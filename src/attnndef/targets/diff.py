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
    field_changes: tuple[tuple[str, tuple[str, str]], ...] = ()

    @property
    def changes(self) -> dict[str, tuple[str, str]]:
        return dict(self.field_changes)

    @property
    def label(self) -> str:
        protocol, port = self.identity
        service = self.current or self.previous
        return f"{port}/{protocol} {service.name if service else 'unknown'}"

@dataclass(frozen=True)
class IntelligenceDiff:
    previous_id: int | None
    current_id: int | None
    entries: tuple[DiffEntry, ...]
    previous_session_id: str = ""
    current_session_id: str = ""
    previous_round_id: int | None = None
    current_round_id: int | None = None

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
        for group, title in ((self.added, "ADDED"), (self.removed, "REMOVED"), (self.changed, "CHANGED"), (self.status_changed, "STATUS_CHANGED")):
            if group:
                lines.append(f"{title}:")
                for entry in group:
                    lines.append(f"  {entry.label}")
                    for field, (old, new) in entry.field_changes:
                        lines.append(f"    {field}: {old} → {new}")
        return "\n".join(lines) if lines else "No observable changes."

def _changes(old: Service, new: Service) -> tuple[tuple[str, tuple[str, str]], ...]:
    values = (("name", (old.name, new.name)), ("version", (old.version, new.version)), ("status", (old.status, new.status)))
    return tuple((field, pair) for field, pair in values if pair[0] != pair[1])

def compare_observations(previous: Observation, current: Observation) -> IntelligenceDiff:
    before = {(s.protocol, s.port): s for s in previous.services}
    after = {(s.protocol, s.port): s for s in current.services}
    entries: list[DiffEntry] = []
    for identity in sorted(after.keys() - before.keys()): entries.append(DiffEntry(DiffKind.ADDED, identity, current=after[identity]))
    for identity in sorted(before.keys() - after.keys()): entries.append(DiffEntry(DiffKind.REMOVED, identity, previous=before[identity]))
    for identity in sorted(before.keys() & after.keys()):
        old, new = before[identity], after[identity]
        changes = _changes(old, new)
        if changes:
            kind = DiffKind.STATUS_CHANGED if old.status != new.status else DiffKind.CHANGED
            entries.append(DiffEntry(kind, identity, old, new, changes))
    return IntelligenceDiff(previous.id, current.id, tuple(entries), previous.session_id, current.session_id, previous.round_id, current.round_id)

def diff_history(history: Iterable[Observation], *, newest_first: bool = True) -> IntelligenceDiff | None:
    observations = list(history)
    if len(observations) < 2: return None
    previous, current = (observations[1], observations[0]) if newest_first else (observations[-2], observations[-1])
    return compare_observations(previous, current)
