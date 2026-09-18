"""Extraction + validation of flags from raw exploit output.

This is intentionally generic: it knows nothing about how the raw output
was obtained (that's the runner's / attack_fn's job) and nothing about a
specific challenge's vulnerability. It only knows a *flag format regex*.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Protocol


class Extractor(Protocol):
    def extract(self, raw_output: str) -> Optional[str]:
        ...


@dataclass
class RegexExtractor:
    """Pulls the first regex match out of raw text.

    pattern default matches a generic `FLAG{...}` style; override per
    competition (UNKNOWN: real flag format is platform/event-specific).
    """
    pattern: str = r"FLAG\{[^{}\s]{1,256}\}"
    flags: int = re.IGNORECASE

    def __post_init__(self) -> None:
        self._re = re.compile(self.pattern, self.flags)

    def extract(self, raw_output: str) -> Optional[str]:
        m = self._re.search(raw_output or "")
        return m.group(0) if m else None


class FlagValidator:
    """Format + dedup validation, kept separate from extraction so both
    can be unit-tested independently and swapped out."""

    def __init__(self, pattern: str = r"^FLAG\{[^{}\s]{1,256}\}$") -> None:
        self._re = re.compile(pattern, re.IGNORECASE)
        self._seen: set[str] = set()

    def is_well_formed(self, flag: Optional[str]) -> bool:
        return bool(flag) and bool(self._re.match(flag))

    def is_duplicate(self, flag: str) -> bool:
        return flag in self._seen

    def accept(self, flag: str) -> bool:
        """Returns True and records the flag iff well-formed and new."""
        if not self.is_well_formed(flag) or self.is_duplicate(flag):
            return False
        self._seen.add(flag)
        return True

    def validate(self, flags: list[str] | str) -> list[str]:
        values = [flags] if isinstance(flags, str) else flags
        return list(dict.fromkeys(flag for flag in values if self.accept(flag)))
