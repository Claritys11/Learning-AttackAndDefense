import tempfile
import time
import pytest

from attnndef.core.models import Evidence
from attnndef.io.sink import LocalSink
from attnndef.operations import (
    ActionCategory,
    AttackStatus,
    DefenseStatus,
    FlagStatus,
    HealthTrajectory,
    MissionStatus,
    OperationService,
    SituationalAwarenessService,
    SlaStatus,
)
from attnndef.targets import Observation, Role, Service, Target, TargetService


def _setup_awareness_env(tmp_dir: str):
    db_path = f"{tmp_dir}/state.db"
    sink_path = f"{tmp_dir}/sink.jsonl"
    sink = LocalSink(sink_path)

    targets = TargetService(db_path)
    targets.add_target(Target(id="enemy-01", name="enemy-01", host="10.0.0.1", role=Role.ENEMY))
    targets.add_target(Target(id="enemy-02", name="enemy-02", host="10.0.0.2", role=Role.ENEMY))

    ops = OperationService(db_path, target_service=targets)
    session = ops.create_session("Awareness Test Session", platform="local")
    ops.start_round(session.session_id, 1)

    wf = ops.create_workflow(
        session_id=session.session_id,
        round_id=1,
        title="Web Investigation",
        target_id="enemy-01",
    )
    return db_path, sink, targets, ops, session, wf


def test_mission_awareness_full_state():
    with tempfile.TemporaryDirectory() as d:
        _, sink, targets, ops, session, wf = _setup_awareness_env(d)

        # Baseline observation: port 8080 and port 22 open
        obs1 = targets.record_observation(
            Observation(
                id=None,
                target_id="enemy-01",
                observed_at=time.time() - 100,
                services=(
                    Service(port=8080, protocol="tcp", name="http", version="Apache/2.4.41"),
                    Service(port=22, protocol="tcp", name="ssh", version="OpenSSH_8.2p1"),
                ),
            )
        )

        m = ops.create_mission(
            workflow_id=wf.workflow_id,
            target_id="enemy-01",
            service_port=8080,
            service_protocol="tcp",
            title="Inspect HTTP",
            objective="Analyze endpoint vulnerabilities",
            initial_observation_id=obs1.id,
        )
        ops.start_mission(m.mission_id)

        # Second observation: port 3306 added
        obs2 = targets.record_observation(
            Observation(
                id=None,
                target_id="enemy-01",
                observed_at=time.time() - 50,
                services=(
                    Service(port=8080, protocol="tcp", name="http", version="Apache/2.4.41"),
                    Service(port=22, protocol="tcp", name="ssh", version="OpenSSH_8.2p1"),
                    Service(port=3306, protocol="tcp", name="mysql", version="5.7.33"),
                ),
            )
        )

        # Write an evidence item to sink
        ev1 = Evidence(
            id="ev-recon-8080",
            ts=time.time() - 80,
            kind="tool_nmap",
            target_id="enemy-01",
            ok=True,
            payload={"summary": "Nmap port scan successful", "tool_execution_id": "exec-001"},
        )
        sink.write(ev1)

        # Record correlated actions and records
        act = ops.record_action(
            session.session_id,
            1,
            ActionCategory.RECON,
            "nmap",
            "port_scan",
            "Port scan 8080",
            target_id="enemy-01",
            workflow_id=wf.workflow_id,
            mission_id=m.mission_id,
            evidence_id=ev1.id,
        )
        atk = ops.record_attack(
            1,
            "enemy-01",
            "http/8080",
            "sqli",
            status=AttackStatus.SUCCESS,
            workflow_id=wf.workflow_id,
            mission_id=m.mission_id,
        )
        defn = ops.record_defense(
            1,
            "enemy-01",
            "http/8080",
            "waf_rule",
            status=DefenseStatus.COMPLETED,
            workflow_id=wf.workflow_id,
            mission_id=m.mission_id,
        )
        flg = ops.record_flag(
            1,
            "enemy-01",
            "sqlmap",
            "flag{secret_exploited_12345}",
            status=FlagStatus.VALIDATED,
            workflow_id=wf.workflow_id,
            mission_id=m.mission_id,
        )
        sla1 = ops.record_sla(
            1,
            "enemy-01",
            "tcp/8080",
            SlaStatus.OK,
            latency_ms=22.4,
            workflow_id=wf.workflow_id,
            mission_id=m.mission_id,
        )
        sla2 = ops.record_sla(
            1,
            "enemy-01",
            "tcp/8080",
            SlaStatus.OK,
            latency_ms=18.6,
            workflow_id=wf.workflow_id,
            mission_id=m.mission_id,
        )

        awareness_svc = SituationalAwarenessService(ops, target_service=targets, sink=sink)
        view = awareness_svc.get_mission_awareness(m.mission_id)

        # 1. Mission & Target context
        assert view.mission_id == m.mission_id
        assert view.title == "Inspect HTTP"
        assert view.target_name == "enemy-01"
        assert view.target_host == "10.0.0.1"
        assert view.target_role == "enemy"
        assert view.workflow_title == "Web Investigation"
        assert view.status == "in_progress"

        # 2. Intelligence context
        assert view.initial_observation_id == obs1.id
        assert view.latest_observation_id == obs2.id
        assert view.is_service_open_now is True
        assert view.diff_summary["added"] == 1  # 3306 added
        assert "3306/tcp" in view.diff_summary["summary"]

        # 3. Health & SLA
        assert view.last_sla_status == "OK"
        assert view.health_trajectory == HealthTrajectory.HEALTHY.value
        assert view.avg_latency_ms == 20.5

        # 4. Operations Breakdown
        assert view.action_count == 1
        assert view.attack_count == 1
        assert view.defense_count == 1
        assert view.flag_count == 1
        assert view.flags_validated == 1

        # 5. Evidence correlation
        assert len(view.evidence_items) >= 1
        matched_ev = next((e for e in view.evidence_items if e.id == ev1.id), None)
        assert matched_ev is not None
        assert matched_ev.summary == "Nmap port scan successful"

        # 6. JSON serialization check
        v_dict = view.to_dict()
        assert v_dict["mission_id"] == m.mission_id
        assert v_dict["health"]["health_trajectory"] == "healthy"
        assert v_dict["intelligence"]["is_service_open_now"] is True


def test_mission_awareness_empty_and_partial_state():
    with tempfile.TemporaryDirectory() as d:
        _, sink, targets, ops, session, wf = _setup_awareness_env(d)

        # Mission without initial observation, without actions, without SLA
        m = ops.create_mission(
            workflow_id=wf.workflow_id,
            target_id="enemy-01",
            service_port=9000,
            title="Empty Mission",
            initial_observation_id=None,
        )

        awareness_svc = SituationalAwarenessService(ops, target_service=targets, sink=sink)
        view = awareness_svc.get_mission_awareness(m.mission_id)

        assert view.initial_observation_id is None
        assert view.latest_observation_id is None
        assert view.is_service_open_now is False
        assert view.diff_summary["summary"] == "No baseline diff available"
        assert view.last_sla_status is None
        assert view.health_trajectory == HealthTrajectory.UNKNOWN.value
        assert view.avg_latency_ms is None
        assert view.action_count == 0
        assert view.attack_count == 0
        assert view.defense_count == 0
        assert view.flag_count == 0
        assert len(view.evidence_items) == 0


def test_mission_awareness_stale_and_closed_service():
    with tempfile.TemporaryDirectory() as d:
        _, sink, targets, ops, session, wf = _setup_awareness_env(d)

        # Initial observation: port 8080 was open
        obs1 = targets.record_observation(
            Observation(
                id=None,
                target_id="enemy-01",
                observed_at=time.time() - 100,
                services=(Service(port=8080, protocol="tcp", name="http"),),
            )
        )
        m = ops.create_mission(
            workflow_id=wf.workflow_id,
            target_id="enemy-01",
            service_port=8080,
            title="Service to be closed",
            initial_observation_id=obs1.id,
        )

        # Newer observation: port 8080 closed / removed
        obs2 = targets.record_observation(
            Observation(
                id=None,
                target_id="enemy-01",
                observed_at=time.time() - 10,
                services=(Service(port=22, protocol="tcp", name="ssh"),),
            )
        )

        awareness_svc = SituationalAwarenessService(ops, target_service=targets, sink=sink)
        view = awareness_svc.get_mission_awareness(m.mission_id)

        assert view.is_service_open_now is False
        assert view.diff_summary["removed"] == 1
        assert "8080/tcp" in view.diff_summary["summary"]


def test_health_trajectory_transitions():
    with tempfile.TemporaryDirectory() as d:
        _, _, _, ops, _, wf = _setup_awareness_env(d)

        m = ops.create_mission(
            workflow_id=wf.workflow_id,
            target_id="enemy-01",
            service_port=8080,
            title="Trajectory Test",
        )

        awareness_svc = SituationalAwarenessService(ops)

        # 0 observations -> UNKNOWN
        assert awareness_svc._compute_health_trajectory([]) == HealthTrajectory.UNKNOWN.value

        # 1 OK observation -> HEALTHY
        sla_ok1 = ops.record_sla(1, "enemy-01", "tcp/8080", SlaStatus.OK, mission_id=m.mission_id)
        view = awareness_svc.get_mission_awareness(m.mission_id)
        assert view.health_trajectory == HealthTrajectory.HEALTHY.value

        # Degrading transition: OK -> OFFLINE
        time.sleep(0.01)
        sla_off1 = ops.record_sla(1, "enemy-01", "tcp/8080", SlaStatus.OFFLINE, mission_id=m.mission_id)
        view = awareness_svc.get_mission_awareness(m.mission_id)
        assert view.health_trajectory == HealthTrajectory.DEGRADING.value

        # Sustained OFFLINE: OFFLINE -> OFFLINE
        time.sleep(0.01)
        sla_off2 = ops.record_sla(1, "enemy-01", "tcp/8080", SlaStatus.OFFLINE, mission_id=m.mission_id)
        view = awareness_svc.get_mission_awareness(m.mission_id)
        assert view.health_trajectory == HealthTrajectory.OFFLINE.value

        # Recovering transition: OFFLINE -> OK
        time.sleep(0.01)
        sla_ok2 = ops.record_sla(1, "enemy-01", "tcp/8080", SlaStatus.OK, mission_id=m.mission_id)
        view = awareness_svc.get_mission_awareness(m.mission_id)
        assert view.health_trajectory == HealthTrajectory.RECOVERING.value


def test_target_awareness_aggregation():
    with tempfile.TemporaryDirectory() as d:
        _, sink, targets, ops, session, wf = _setup_awareness_env(d)

        targets.record_observation(
            Observation(
                id=None,
                target_id="enemy-01",
                observed_at=time.time(),
                services=(Service(port=80, protocol="tcp", name="http"), Service(port=22, protocol="tcp", name="ssh")),
            )
        )
        m1 = ops.create_mission(wf.workflow_id, "enemy-01", 80, title="Web Mission")
        m2 = ops.create_mission(wf.workflow_id, "enemy-01", 22, title="SSH Mission")

        ops.record_action(session.session_id, 1, ActionCategory.RECON, "nmap", "scan", "Scan enemy", target_id="enemy-01")
        ops.record_attack(1, "enemy-01", "http/80", "lfi", status=AttackStatus.SUCCESS)
        ops.record_defense(1, "enemy-01", "http/80", "patch", status=DefenseStatus.COMPLETED)
        ops.record_flag(1, "enemy-01", "manual", "flag{target_test}")
        ops.record_sla(1, "enemy-01", "tcp/80", SlaStatus.OK)

        awareness_svc = SituationalAwarenessService(ops, target_service=targets, sink=sink)
        t_view = awareness_svc.get_target_awareness("enemy-01")

        assert t_view.target_id == "enemy-01"
        assert t_view.target_host == "10.0.0.1"
        assert len(t_view.missions) == 2
        assert t_view.total_actions == 1
        assert t_view.total_attacks == 1
        assert t_view.total_defenses == 1
        assert t_view.total_flags == 1
        assert t_view.last_health_status == "OK"
        assert len(t_view.latest_services) == 2


def test_evidence_inspection():
    with tempfile.TemporaryDirectory() as d:
        _, sink, targets, ops, _, _ = _setup_awareness_env(d)

        ev = Evidence(
            id="ev-inspect-01",
            ts=time.time(),
            kind="tool_http",
            target_id="enemy-01",
            ok=True,
            payload={"status_code": 200, "body": "OK response"},
        )
        sink.write(ev)

        awareness_svc = SituationalAwarenessService(ops, target_service=targets, sink=sink)

        # Inspect found evidence
        detail = awareness_svc.inspect_evidence("ev-inspect-01")
        assert detail is not None
        assert detail.id == "ev-inspect-01"
        assert detail.kind == "tool_http"
        assert detail.ok is True
        assert detail.payload["status_code"] == 200

        # Inspect non-existent evidence
        none_detail = awareness_svc.inspect_evidence("non-existent-id")
        assert none_detail is None


def test_security_no_plaintext_flags_in_awareness():
    with tempfile.TemporaryDirectory() as d:
        _, sink, targets, ops, session, wf = _setup_awareness_env(d)

        raw_flag = "flag{ultra_confidential_flag_text_12345}"
        m = ops.create_mission(wf.workflow_id, "enemy-01", 8080, title="Flag Security Mission")

        ops.record_flag(
            1,
            "enemy-01",
            "exploit",
            raw_flag,
            workflow_id=wf.workflow_id,
            mission_id=m.mission_id,
        )

        awareness_svc = SituationalAwarenessService(ops, target_service=targets, sink=sink)
        view = awareness_svc.get_mission_awareness(m.mission_id)

        # Verify plaintext flag is not in FlagRecordView
        assert len(view.recent_flags) == 1
        rf = view.recent_flags[0]
        assert raw_flag not in rf.fingerprint
        assert raw_flag not in rf.flag_preview
        assert rf.flag_preview.startswith("flag{...")

        # Verify serialized dict does not contain raw flag
        v_dict = view.to_dict()
        dict_str = str(v_dict)
        assert raw_flag not in dict_str
