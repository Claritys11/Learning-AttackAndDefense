"""Domain models shared across attack/defense modules.

Scope note: these models describe *local fixture/mock* targets only.
Nothing here talks to a real CTF platform (e.g. GZCTF). Fields that would
only make sense once a platform integration exists are intentionally
absent -- see README "UNKNOWN" section.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


def _now() -> float:
    return time.time()


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


class Role(str, Enum):
    OWN = "own"       # a target we must defend
    ENEMY = "enemy"   # a target we may attack
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Target:
    """A single local fixture/mock service instance.

    host/port point at localhost-only fixtures in this design's scope.
    `metadata` is an open bag for challenge-specific fields (e.g. config
    file path for the defense patcher).
    """
    id: str
    name: str
    host: str
    port: int
    role: Role = Role.UNKNOWN
    tags: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def address(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class ExploitResult:
    target_id: str
    success: bool
    raw_output: str = ""
    flag: Optional[str] = None
    error: Optional[str] = None
    duration_s: float = 0.0
    id: str = field(default_factory=_new_id)
    ts: float = field(default_factory=_now)

    def to_evidence(self, kind: str = "attack") -> "Evidence":
        return Evidence(
            id=self.id,
            ts=self.ts,
            kind=kind,
            target_id=self.target_id,
            ok=self.success,
            payload={
                "flag": self.flag,
                "error": self.error,
                "duration_s": self.duration_s,
                "raw_output_len": len(self.raw_output),
            },
        )


@dataclass
class Evidence:
    """Structured, JSON-serializable record written to the local sink."""
    id: str
    ts: float
    kind: str  # "attack" | "extract" | "submit" | "patch" | "health" | "replay"
    target_id: str
    ok: bool
    payload: dict[str, Any] = field(default_factory=dict)

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ts": self.ts,
            "kind": self.kind,
            "target_id": self.target_id,
            "ok": self.ok,
            "payload": self.payload,
        }


@dataclass
class PatchPlan:
    """Represents one defense change: a diff between current and desired
    state of a target's fixture config, with an explicit lifecycle.

    dry_run -> apply -> (rollback | keep)
    """
    id: str
    target_id: str
    description: str
    backup_path: Optional[str] = None
    dry_run: bool = True
    applied: bool = False
    applied_at: Optional[float] = None
    rolled_back: bool = False
    diff_preview: str = ""

    @staticmethod
    def new(target_id: str, description: str) -> "PatchPlan":
        return PatchPlan(id=_new_id(), target_id=target_id, description=description)


@dataclass
class HealthResult:
    target_id: str
    ok: bool
    latency_ms: float
    details: str = ""
    ts: float = field(default_factory=_now)
