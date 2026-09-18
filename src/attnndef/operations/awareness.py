"""Situational Awareness Aggregation Service.

Pure read-only aggregation layer that compiles operational facts, target intelligence,
service health trajectories, and correlated evidence into unified views.
Strictly zero side effects and zero state mutations.
"""
from __future__ import annotations

import time
from typing import Any

from ..io.sink import LocalSink
from ..targets.diff import compare_observations
from ..targets.service import TargetService
from .awareness_models import (
    CorrelatedEvidenceItem,
    EvidenceDetailView,
    FlagRecordView,
    HealthTrajectory,
    MissionAwarenessView,
    TargetAwarenessView,
)
from .models import FlagStatus, SlaObservation, SlaStatus
from .service import OperationService


class SituationalAwarenessService:
    """Read-only aggregation and correlation service for Attack & Defense operations."""

    def __init__(
        self,
        operation_service: OperationService,
        target_service: TargetService | None = None,
        sink: LocalSink | None = None,
    ) -> None:
        self.ops = operation_service
        self.targets = target_service
        self.sink = sink

    def get_mission_awareness(self, mission_id: str) -> MissionAwarenessView:
        """Compile a complete situational awareness view for a specific Mission."""
        m = self.ops.get_mission(mission_id)
        if not m:
            raise ValueError(f"Mission not found: {mission_id}")

        # Workflow Context
        wf = self.ops.get_workflow(m.workflow_id)
        wf_title = wf.title if wf else "Unknown Workflow"
        wf_status = wf.status.value if wf else "unknown"
        round_id = wf.round_id if wf else 0
        session_id = wf.session_id if wf else ""

        # Target Posture
        tgt = self.targets.get_target(m.target_id) if self.targets else None
        tgt_name = tgt.name if tgt else m.target_id
        tgt_host = tgt.host if tgt else ""
        tgt_role = tgt.role.value if tgt else "unknown"

        # Intelligence Context
        hist = self.targets.history(m.target_id, limit=50) if self.targets else []
        latest_obs = hist[0] if hist else None

        initial_obs = None
        if m.initial_observation_id is not None:
            initial_obs = next((o for o in hist if o.id == m.initial_observation_id), None)
            if not initial_obs and self.targets:
                # Fallback: search wider history
                wider = self.targets.history(m.target_id, limit=200)
                initial_obs = next((o for o in wider if o.id == m.initial_observation_id), None)

        is_open = False
        if latest_obs and latest_obs.services:
            is_open = any(
                s.port == m.service_port and s.protocol.lower() == m.service_protocol.lower()
                for s in latest_obs.services
            )

        diff_summary: dict[str, Any] = {
            "summary": "No baseline diff available",
            "added": 0,
            "removed": 0,
            "changed": 0,
        }
        if initial_obs and latest_obs and initial_obs.id != latest_obs.id:
            diff = compare_observations(initial_obs, latest_obs)
            diff_summary = {
                "summary": diff.render(),
                "added": len(diff.added),
                "removed": len(diff.removed),
                "changed": len(diff.changed),
            }
        elif initial_obs and latest_obs and initial_obs.id == latest_obs.id:
            diff_summary = {
                "summary": f"Current observation #{latest_obs.id} matches initial baseline",
                "added": 0,
                "removed": 0,
                "changed": 0,
            }

        initial_services_tuple = (
            tuple(
                {"port": s.port, "protocol": s.protocol, "name": s.name, "version": s.version}
                for s in initial_obs.services
            )
            if initial_obs
            else ()
        )
        latest_services_tuple = (
            tuple(
                {"port": s.port, "protocol": s.protocol, "name": s.name, "version": s.version}
                for s in latest_obs.services
            )
            if latest_obs
            else ()
        )

        # Health & SLA Trajectory
        slas = self.ops.list_sla(mission_id=m.mission_id, limit=20)
        if not slas:
            # Check target SLA matching port/protocol
            candidate_slas = self.ops.list_sla(target_id=m.target_id, limit=20)
            service_tag = f"{m.service_protocol}/{m.service_port}".lower()
            slas = [
                s for s in candidate_slas
                if s.service.lower() in (service_tag, str(m.service_port))
            ]

        last_sla = slas[0] if slas else None
        last_sla_status = last_sla.status.value.upper() if last_sla else None
        latencies = [s.latency_ms for s in slas if s.latency_ms is not None]
        avg_lat = round(sum(latencies) / len(latencies), 2) if latencies else None

        trajectory = self._compute_health_trajectory(slas)

        # Operations Breakdown
        actions = self.ops.list_actions(mission_id=m.mission_id, limit=100)
        attacks = self.ops.list_attacks(mission_id=m.mission_id, limit=100)
        defenses = self.ops.list_defenses(mission_id=m.mission_id, limit=100)
        flags = self.ops.list_flags(mission_id=m.mission_id, limit=100)
        timeline = self.ops.get_mission_timeline(m.mission_id, limit=100)

        attacks_by_status: dict[str, int] = {}
        for atk in attacks:
            st = atk.status.value
            attacks_by_status[st] = attacks_by_status.get(st, 0) + 1

        defenses_by_status: dict[str, int] = {}
        for df in defenses:
            st = df.status.value
            defenses_by_status[st] = defenses_by_status.get(st, 0) + 1

        flags_obs = len(flags)
        flags_val = sum(1 for f in flags if f.status == FlagStatus.VALIDATED)
        flags_sub = sum(1 for f in flags if f.status == FlagStatus.SUBMITTED)
        flags_rej = sum(1 for f in flags if f.status == FlagStatus.REJECTED)

        recent_flags = tuple(
            FlagRecordView(
                id=f.id,
                round_id=f.round_id,
                target_id=f.target_id,
                source=f.source,
                observed_at=f.observed_at,
                status=f.status.value,
                fingerprint=f.fingerprint,
                flag_preview=f.flag_preview,
                notes=f.notes,
                evidence_id=f.evidence_id,
            )
            for f in flags[:10]
        )

        # Correlated Evidence
        referenced_evidence_ids: set[str] = set()
        for rec in actions:
            if rec.evidence_id:
                referenced_evidence_ids.add(rec.evidence_id)
        for atk in attacks:
            if atk.evidence_id:
                referenced_evidence_ids.add(atk.evidence_id)
        for df in defenses:
            if df.evidence_id:
                referenced_evidence_ids.add(df.evidence_id)
        for flg in flags:
            if flg.evidence_id:
                referenced_evidence_ids.add(flg.evidence_id)

        evidence_items: list[CorrelatedEvidenceItem] = []
        if self.sink:
            all_sink_rows = self.sink.read_all()
            for row in all_sink_rows:
                rid = row.get("id", "")
                target_match = row.get("target_id") == m.target_id
                if rid in referenced_evidence_ids or (target_match and rid.startswith(m.target_id)):
                    payload = row.get("payload", {})
                    evidence_items.append(
                        CorrelatedEvidenceItem(
                            id=rid,
                            ts=row.get("ts", 0.0),
                            kind=row.get("kind", "unknown"),
                            target_id=row.get("target_id", m.target_id),
                            ok=bool(row.get("ok", True)),
                            summary=payload.get("summary", ""),
                            tool_execution_id=payload.get("tool_execution_id"),
                            operation=payload.get("operation", ""),
                            payload=payload,
                        )
                    )

        return MissionAwarenessView(
            mission_id=m.mission_id,
            workflow_id=m.workflow_id,
            target_id=m.target_id,
            service_port=m.service_port,
            service_protocol=m.service_protocol,
            title=m.title,
            objective=m.objective,
            status=m.status.value,
            created_at=m.created_at,
            completed_at=m.completed_at,
            notes=m.notes,
            target_name=tgt_name,
            target_host=tgt_host,
            target_role=tgt_role,
            workflow_title=wf_title,
            workflow_status=wf_status,
            round_id=round_id,
            session_id=session_id,
            initial_observation_id=m.initial_observation_id,
            initial_observed_at=initial_obs.observed_at if initial_obs else None,
            initial_services=initial_services_tuple,
            latest_observation_id=latest_obs.id if latest_obs else None,
            latest_observed_at=latest_obs.observed_at if latest_obs else None,
            latest_services=latest_services_tuple,
            is_service_open_now=is_open,
            diff_summary=diff_summary,
            sla_history=tuple(slas),
            last_sla_status=last_sla_status,
            health_trajectory=trajectory,
            avg_latency_ms=avg_lat,
            action_count=len(actions),
            attack_count=len(attacks),
            defense_count=len(defenses),
            flag_count=len(flags),
            sla_count=len(slas),
            attacks_by_status=attacks_by_status,
            defenses_by_status=defenses_by_status,
            flags_observed=flags_obs,
            flags_validated=flags_val,
            flags_submitted=flags_sub,
            flags_rejected=flags_rej,
            recent_flags=recent_flags,
            timeline=tuple(timeline),
            evidence_items=tuple(evidence_items),
        )

    def get_target_awareness(self, target_id: str, session_id: str | None = None) -> TargetAwarenessView:
        """Compile consolidated situational awareness across all operations on a target host."""
        tgt = self.targets.get_target(target_id) if self.targets else None
        tgt_name = tgt.name if tgt else target_id
        tgt_host = tgt.host if tgt else ""
        tgt_role = tgt.role.value if tgt else "unknown"

        hist = self.targets.history(target_id, limit=20) if self.targets else []
        latest_obs = hist[0] if hist else None
        latest_services_tuple = (
            tuple(
                {"port": s.port, "protocol": s.protocol, "name": s.name, "version": s.version}
                for s in latest_obs.services
            )
            if latest_obs
            else ()
        )

        all_missions = self.ops.list_missions()
        target_missions = [m for m in all_missions if m.target_id == target_id]
        missions_dicts = tuple(
            {
                "mission_id": m.mission_id,
                "title": m.title,
                "port": m.service_port,
                "protocol": m.service_protocol,
                "status": m.status.value,
                "workflow_id": m.workflow_id,
            }
            for m in target_missions
        )

        # Operational records
        actions = self.ops.list_actions(target_id=target_id, limit=200)
        attacks = self.ops.list_attacks(target_id=target_id, limit=200)
        defenses = self.ops.list_defenses(target_id=target_id, limit=200)
        flags = self.ops.list_flags(target_id=target_id, limit=200)
        slas = self.ops.list_sla(target_id=target_id, limit=20)
        timeline = self.ops.get_timeline(target_id=target_id, limit=50)

        active_wf = None
        for a in actions:
            if a.workflow_id:
                wf = self.ops.get_workflow(a.workflow_id)
                if wf and wf.status.value == "in_progress":
                    active_wf = wf.workflow_id
                    break

        last_health = slas[0].status.value.upper() if slas else "UNKNOWN"

        return TargetAwarenessView(
            target_id=target_id,
            target_name=tgt_name,
            target_host=tgt_host,
            target_role=tgt_role,
            latest_observation_id=latest_obs.id if latest_obs else None,
            latest_observed_at=latest_obs.observed_at if latest_obs else None,
            latest_services=latest_services_tuple,
            missions=missions_dicts,
            active_workflow_id=active_wf,
            total_actions=len(actions),
            total_attacks=len(attacks),
            total_defenses=len(defenses),
            total_flags=len(flags),
            last_health_status=last_health,
            timeline=tuple(timeline),
        )

    def inspect_evidence(self, evidence_id: str) -> EvidenceDetailView | None:
        """Inspect a specific evidence item from the local sink."""
        if not self.sink:
            return None
        rows = self.sink.read_all()
        for row in rows:
            if row.get("id") == evidence_id:
                return EvidenceDetailView(
                    id=row.get("id", evidence_id),
                    ts=row.get("ts", 0.0),
                    kind=row.get("kind", "unknown"),
                    target_id=row.get("target_id", "unknown"),
                    ok=bool(row.get("ok", True)),
                    payload=row.get("payload", {}),
                )
        return None

    @staticmethod
    def _compute_health_trajectory(slas: list[SlaObservation]) -> str:
        """Deterministic computation of health trajectory based on recent SLA observations."""
        if not slas:
            return HealthTrajectory.UNKNOWN.value

        # Reverse so chronological order is oldest -> newest
        chrono = list(reversed(slas))
        if len(chrono) == 1:
            if chrono[0].status == SlaStatus.OK:
                return HealthTrajectory.HEALTHY.value
            return HealthTrajectory.OFFLINE.value

        latest = chrono[-1].status
        previous = chrono[-2].status

        if latest == SlaStatus.OK and previous == SlaStatus.OK:
            return HealthTrajectory.HEALTHY.value
        elif latest in (SlaStatus.OFFLINE, SlaStatus.MUMBLE) and previous == SlaStatus.OK:
            return HealthTrajectory.DEGRADING.value
        elif latest in (SlaStatus.OFFLINE, SlaStatus.MUMBLE) and previous in (SlaStatus.OFFLINE, SlaStatus.MUMBLE):
            return HealthTrajectory.OFFLINE.value
        elif latest == SlaStatus.OK and previous in (SlaStatus.OFFLINE, SlaStatus.MUMBLE):
            return HealthTrajectory.RECOVERING.value

        return latest.value
