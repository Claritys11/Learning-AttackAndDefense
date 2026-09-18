"""Domain view models for Operator Situational Awareness.

These models are strictly read-only, non-authoritative presentation structures
that aggregate existing state from Target Intelligence, Operational Core,
Workflows, Missions, and LocalSink Evidence.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from .models import SlaObservation, TimelineEntry


class HealthTrajectory(str, Enum):
    HEALTHY = "healthy"
    DEGRADING = "degrading"
    OFFLINE = "offline"
    RECOVERING = "recovering"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class CorrelatedEvidenceItem:
    id: str
    ts: float
    kind: str
    target_id: str
    ok: bool
    summary: str = ""
    tool_execution_id: str | None = None
    operation: str = ""
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FlagRecordView:
    id: str
    round_id: int
    target_id: str
    source: str
    observed_at: float
    status: str
    fingerprint: str
    flag_preview: str
    notes: str = ""
    evidence_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MissionAwarenessView:
    """Consolidated situational awareness for a concrete operator mission."""

    # Mission Context
    mission_id: str
    workflow_id: str
    target_id: str
    service_port: int
    service_protocol: str
    title: str
    objective: str
    status: str
    created_at: float
    completed_at: float | None
    notes: str

    # Target Context
    target_name: str
    target_host: str
    target_role: str

    # Workflow Context
    workflow_title: str
    workflow_status: str
    round_id: int
    session_id: str

    # Target Intelligence Context
    initial_observation_id: int | None
    initial_observed_at: float | None
    initial_services: tuple[dict[str, Any], ...]
    latest_observation_id: int | None
    latest_observed_at: float | None
    latest_services: tuple[dict[str, Any], ...]
    is_service_open_now: bool
    diff_summary: dict[str, Any]

    # Service Health & SLA
    sla_history: tuple[SlaObservation, ...]
    last_sla_status: str | None
    health_trajectory: str
    avg_latency_ms: float | None

    # Operations Breakdown
    action_count: int
    attack_count: int
    defense_count: int
    flag_count: int
    sla_count: int
    attacks_by_status: dict[str, int]
    defenses_by_status: dict[str, int]

    # Flag Lifecycle (No plaintext flags)
    flags_observed: int
    flags_validated: int
    flags_submitted: int
    flags_rejected: int
    recent_flags: tuple[FlagRecordView, ...]

    # Timeline & Evidence
    timeline: tuple[TimelineEntry, ...]
    evidence_items: tuple[CorrelatedEvidenceItem, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "workflow_id": self.workflow_id,
            "target_id": self.target_id,
            "service_port": self.service_port,
            "service_protocol": self.service_protocol,
            "title": self.title,
            "objective": self.objective,
            "status": self.status,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "notes": self.notes,
            "target": {
                "id": self.target_id,
                "name": self.target_name,
                "host": self.target_host,
                "role": self.target_role,
            },
            "workflow": {
                "id": self.workflow_id,
                "title": self.workflow_title,
                "status": self.workflow_status,
                "round_id": self.round_id,
                "session_id": self.session_id,
            },
            "intelligence": {
                "initial_observation_id": self.initial_observation_id,
                "initial_observed_at": self.initial_observed_at,
                "initial_services": list(self.initial_services),
                "latest_observation_id": self.latest_observation_id,
                "latest_observed_at": self.latest_observed_at,
                "latest_services": list(self.latest_services),
                "is_service_open_now": self.is_service_open_now,
                "diff_summary": self.diff_summary,
            },
            "health": {
                "last_sla_status": self.last_sla_status,
                "health_trajectory": self.health_trajectory,
                "avg_latency_ms": self.avg_latency_ms,
                "recent_sla": [asdict(s) for s in self.sla_history],
            },
            "operations": {
                "action_count": self.action_count,
                "attack_count": self.attack_count,
                "defense_count": self.defense_count,
                "flag_count": self.flag_count,
                "sla_count": self.sla_count,
                "attacks_by_status": self.attacks_by_status,
                "defenses_by_status": self.defenses_by_status,
            },
            "flags": {
                "observed": self.flags_observed,
                "validated": self.flags_validated,
                "submitted": self.flags_submitted,
                "rejected": self.flags_rejected,
                "recent": [f.to_dict() for f in self.recent_flags],
            },
            "timeline": [asdict(e) for e in self.timeline],
            "evidence": [e.to_dict() for e in self.evidence_items],
        }


@dataclass(frozen=True)
class TargetAwarenessView:
    """Consolidated situational awareness for an entire target host."""

    target_id: str
    target_name: str
    target_host: str
    target_role: str
    latest_observation_id: int | None
    latest_observed_at: float | None
    latest_services: tuple[dict[str, Any], ...]
    missions: tuple[dict[str, Any], ...]
    active_workflow_id: str | None
    total_actions: int
    total_attacks: int
    total_defenses: int
    total_flags: int
    last_health_status: str
    timeline: tuple[TimelineEntry, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "target_name": self.target_name,
            "target_host": self.target_host,
            "role": self.target_role,
            "latest_observation_id": self.latest_observation_id,
            "latest_observed_at": self.latest_observed_at,
            "latest_services": list(self.latest_services),
            "missions": list(self.missions),
            "active_workflow_id": self.active_workflow_id,
            "operations_summary": {
                "total_actions": self.total_actions,
                "total_attacks": self.total_attacks,
                "total_defenses": self.total_defenses,
                "total_flags": self.total_flags,
                "last_health_status": self.last_health_status,
            },
            "timeline": [asdict(e) for e in self.timeline],
        }


@dataclass(frozen=True)
class EvidenceDetailView:
    """Read-only inspection view of an evidence record."""

    id: str
    ts: float
    kind: str
    target_id: str
    ok: bool
    payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
