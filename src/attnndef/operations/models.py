from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import time
from typing import Any


class SessionStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    ENDED = "ended"


@dataclass(frozen=True)
class Session:
    session_id: str
    competition: str
    platform: str
    team_id: str
    operator: str
    vpn_interface: str = "wg0"
    own_ip: str = ""
    enemy_subnet: str = ""
    started_at: float = field(default_factory=time.time)
    ended_at: float | None = None
    status: SessionStatus = SessionStatus.ACTIVE


class RoundStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    ENDED = "ended"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Round:
    round_id: int
    session_id: str
    round_number: int
    started_at: float = field(default_factory=time.time)
    ended_at: float | None = None
    status: RoundStatus = RoundStatus.ACTIVE


@dataclass(frozen=True)
class Tick:
    id: int | None
    session_id: str
    round_id: int
    tick_number: int
    observed_at: float = field(default_factory=time.time)
    status: str = "observed"


class WorkflowStatus(str, Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    ABORTED = "aborted"


@dataclass(frozen=True)
class WorkflowRun:
    workflow_id: str
    session_id: str
    round_id: int
    title: str
    objective: str = ""
    target_id: str | None = None
    started_at: float = field(default_factory=time.time)
    completed_at: float | None = None
    status: WorkflowStatus = WorkflowStatus.ACTIVE
    notes: str = ""


class ActionCategory(str, Enum):
    RECON = "recon"
    ATTACK = "attack"
    DEFENSE = "defense"
    FLAG = "flag"
    VERIFICATION = "verification"
    SYSTEM = "system"


@dataclass(frozen=True)
class OperatorAction:
    id: str
    session_id: str
    round_id: int
    timestamp: float
    category: ActionCategory
    target_id: str | None = None
    tool: str = ""
    operation: str = ""
    summary: str = ""
    status: str = "completed"
    evidence_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    workflow_id: str | None = None
    parent_action_id: str | None = None
    tool_execution_id: str | None = None


class AttackStatus(str, Enum):
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    ABORTED = "aborted"


@dataclass(frozen=True)
class AttackRecord:
    id: str
    round_id: int
    target_id: str
    service: str
    method: str
    status: AttackStatus = AttackStatus.PLANNED
    started_at: float = field(default_factory=time.time)
    completed_at: float | None = None
    notes: str = ""
    evidence_id: str | None = None
    workflow_id: str | None = None


class DefenseStatus(str, Enum):
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    REVERTED = "reverted"


@dataclass(frozen=True)
class DefenseRecord:
    id: str
    round_id: int
    target_id: str
    service: str
    action: str
    status: DefenseStatus = DefenseStatus.PLANNED
    started_at: float = field(default_factory=time.time)
    completed_at: float | None = None
    notes: str = ""
    evidence_id: str | None = None
    workflow_id: str | None = None


class FlagStatus(str, Enum):
    OBSERVED = "observed"
    VALIDATED = "validated"
    SUBMITTED = "submitted"
    REJECTED = "rejected"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class FlagRecord:
    id: str
    round_id: int
    target_id: str
    source: str
    observed_at: float = field(default_factory=time.time)
    status: FlagStatus = FlagStatus.OBSERVED
    fingerprint: str = ""
    flag_preview: str = ""
    notes: str = ""
    evidence_id: str | None = None
    workflow_id: str | None = None


class SlaStatus(str, Enum):
    OK = "ok"
    MUMBLE = "mumble"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SlaObservation:
    id: str
    round_id: int
    target_id: str
    service: str
    observed_at: float = field(default_factory=time.time)
    status: SlaStatus = SlaStatus.OK
    latency_ms: float | None = None
    source: str = "local"
    details: dict[str, Any] = field(default_factory=dict)
    workflow_id: str | None = None


@dataclass(frozen=True)
class TimelineEntry:
    timestamp: float
    category: str
    target_id: str | None
    item_id: str
    round_id: int
    title: str
    status: str
    details: str = ""
    workflow_id: str | None = None


def make_flag_fingerprint(raw_flag: str) -> tuple[str, str]:
    """Compute sha256 fingerprint and masked preview (e.g. flag{...1a2b}).
    Never stores or persists raw flag text.
    """
    cleaned = raw_flag.strip()
    fp = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()
    if len(cleaned) > 10 and cleaned.startswith("flag{") and cleaned.endswith("}"):
        preview = f"flag{{...{cleaned[-6:-1]}}}"
    elif len(cleaned) > 8:
        preview = f"{cleaned[:3]}...{cleaned[-4:]}"
    else:
        preview = f"<{len(cleaned)} chars>"
    return fp, preview
