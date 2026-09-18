import sqlite3
import tempfile
import time
import pytest

from attnndef.context import ContextStore, OperatorContext
from attnndef.operations import (
    ActionCategory,
    AttackStatus,
    DefenseStatus,
    FlagStatus,
    Mission,
    MissionStatus,
    OperationService,
    SlaStatus,
    WorkflowStatus,
)
from attnndef.targets import Observation, Role, Service, Target, TargetService


def _setup_service(tmp_dir: str):
    db_path = f"{tmp_dir}/test.db"
    targets = TargetService(db_path)
    targets.add_target(Target(id="enemy-01", name="enemy-01", host="10.0.0.1", role=Role.ENEMY))
    targets.add_target(Target(id="enemy-02", name="enemy-02", host="10.0.0.2", role=Role.ENEMY))
    targets.add_target(Target(id="own-01", name="own-01", host="10.0.0.10", role=Role.OWN))

    ops = OperationService(db_path, target_service=targets)
    session = ops.create_session("Test Session", platform="local")
    ops.start_round(session.session_id, 1)
    wf = ops.create_workflow(
        session_id=session.session_id,
        round_id=1,
        title="Investigate Enemy",
        target_id="enemy-01",
    )
    return db_path, targets, ops, session, wf


def test_mission_lifecycle_and_state_machine():
    with tempfile.TemporaryDirectory() as d:
        _, _, ops, _, wf = _setup_service(d)

        # Create Mission: initially OPEN
        m = ops.create_mission(
            workflow_id=wf.workflow_id,
            target_id="enemy-01",
            service_port=8080,
            service_protocol="tcp",
            title="Investigate HTTP 8080",
            objective="Inspect unexpected endpoint behavior",
            notes="Initial notes",
        )
        assert m.status == MissionStatus.OPEN
        assert m.service_port == 8080
        assert m.service_protocol == "tcp"
        assert m.completed_at is None

        # Start Mission: OPEN -> IN_PROGRESS
        assert ops.start_mission(m.mission_id) is True
        m_prog = ops.get_mission(m.mission_id)
        assert m_prog.status == MissionStatus.IN_PROGRESS

        # Redundant start is idempotent
        assert ops.start_mission(m.mission_id) is True

        # Complete Mission: IN_PROGRESS -> COMPLETED
        assert ops.complete_mission(m.mission_id, notes="Investigation complete") is True
        m_done = ops.get_mission(m.mission_id)
        assert m_done.status == MissionStatus.COMPLETED
        assert m_done.completed_at is not None
        assert m_done.notes == "Investigation complete"

        # Terminal state: cannot start completed mission
        with pytest.raises(ValueError, match="terminal status"):
            ops.start_mission(m.mission_id)

        # Terminal state: cannot abort completed mission
        with pytest.raises(ValueError, match="Cannot abort completed mission"):
            ops.abort_mission(m.mission_id)

        # Create another mission to test abort flow
        m2 = ops.create_mission(
            workflow_id=wf.workflow_id,
            target_id="enemy-01",
            service_port=22,
            title="Inspect SSH",
        )
        ops.start_mission(m2.mission_id)
        assert ops.abort_mission(m2.mission_id, notes="Aborted due to network partition") is True
        m2_aborted = ops.get_mission(m2.mission_id)
        assert m2_aborted.status == MissionStatus.ABORTED
        assert m2_aborted.completed_at is not None

        # Terminal state: cannot complete aborted mission
        with pytest.raises(ValueError, match="Cannot complete aborted mission"):
            ops.complete_mission(m2.mission_id)

        # Terminal state: cannot start aborted mission
        with pytest.raises(ValueError, match="terminal status"):
            ops.start_mission(m2.mission_id)


def test_mission_validation():
    with tempfile.TemporaryDirectory() as d:
        _, targets, ops, session, wf = _setup_service(d)

        # Unknown workflow
        with pytest.raises(ValueError, match="Workflow not found"):
            ops.create_mission("fake-wf-id", "enemy-01", 80, title="Bad WF")

        # Unknown target
        with pytest.raises(ValueError, match="target not found in registry"):
            ops.create_mission(wf.workflow_id, "nonexistent-target", 80, title="Bad Target")

        # Port validation: 1 <= port <= 65535
        with pytest.raises(ValueError, match="Invalid service port"):
            ops.create_mission(wf.workflow_id, "enemy-01", 0, title="Bad Port 0")
        with pytest.raises(ValueError, match="Invalid service port"):
            ops.create_mission(wf.workflow_id, "enemy-01", -1, title="Negative Port")
        with pytest.raises(ValueError, match="Invalid service port"):
            ops.create_mission(wf.workflow_id, "enemy-01", 65536, title="Bad Port 65536")

        # Protocol validation: "tcp" or "udp" only
        with pytest.raises(ValueError, match="Invalid service protocol"):
            ops.create_mission(wf.workflow_id, "enemy-01", 80, service_protocol="icmp", title="Bad Protocol")
        with pytest.raises(ValueError, match="Invalid service protocol"):
            ops.create_mission(wf.workflow_id, "enemy-01", 80, service_protocol="ftp", title="Bad Protocol")

        # Initial observation validation: must belong to target
        obs_other = targets.record_observation(
            Observation(
                id=None,
                target_id="enemy-02",
                observed_at=time.time(),
                services=(Service(port=80, name="http"),),
            )
        )
        with pytest.raises(ValueError, match="Observation .* not found for target enemy-01"):
            ops.create_mission(
                wf.workflow_id,
                "enemy-01",
                80,
                title="Bad Obs Link",
                initial_observation_id=obs_other.id,
            )

        # Service existence in observation: port/protocol must exist in matched observation
        obs_correct = targets.record_observation(
            Observation(
                id=None,
                target_id="enemy-01",
                observed_at=time.time(),
                services=(Service(port=8080, protocol="tcp", name="http"),),
            )
        )
        with pytest.raises(ValueError, match="Service TCP:22 not found in observation"):
            ops.create_mission(
                wf.workflow_id,
                "enemy-01",
                22,
                title="Port Missing in Obs",
                initial_observation_id=obs_correct.id,
            )
        with pytest.raises(ValueError, match="Service UDP:8080 not found in observation"):
            ops.create_mission(
                wf.workflow_id,
                "enemy-01",
                8080,
                service_protocol="udp",
                title="Protocol Missing in Obs",
                initial_observation_id=obs_correct.id,
            )

        # Correct initial observation with matching service
        m = ops.create_mission(
            wf.workflow_id,
            "enemy-01",
            8080,
            service_protocol="tcp",
            title="Good Obs Link",
            initial_observation_id=obs_correct.id,
        )
        assert m.initial_observation_id == obs_correct.id
        assert not hasattr(m, "current_observation_id")  # Never store current_observation_id on Mission

        # Creation without observation succeeds (no forced scan)
        m_no_obs = ops.create_mission(
            wf.workflow_id,
            "enemy-01",
            3306,
            service_protocol="tcp",
            title="No Obs Mission",
            initial_observation_id=None,
        )
        assert m_no_obs.initial_observation_id is None


def test_cross_target_and_cross_workflow_rejection():
    with tempfile.TemporaryDirectory() as d:
        _, _, ops, session, wf1 = _setup_service(d)

        wf2 = ops.create_workflow(
            session_id=session.session_id,
            round_id=1,
            title="Workflow 2",
            target_id="enemy-02",
        )

        m = ops.create_mission(wf1.workflow_id, "enemy-01", 8080, title="Mission 1")
        m_second = ops.create_mission(wf1.workflow_id, "enemy-01", 8080, title="Mission 2")

        # Action on different target rejected
        act_diff_target = ops.record_action(
            session.session_id,
            1,
            ActionCategory.RECON,
            "nmap",
            "scan",
            "Scan enemy-02",
            target_id="enemy-02",
        )
        with pytest.raises(ValueError, match="Cross-target attachment rejected"):
            ops.attach_action_to_mission(act_diff_target.id, m.mission_id)

        # Action on different workflow rejected
        act_diff_wf = ops.record_action(
            session.session_id,
            1,
            ActionCategory.RECON,
            "nmap",
            "scan",
            "Scan enemy-01 under wf2",
            target_id="enemy-01",
            workflow_id=wf2.workflow_id,
        )
        with pytest.raises(ValueError, match="Cross-workflow attachment rejected"):
            ops.attach_action_to_mission(act_diff_wf.id, m.mission_id)

        # Cross-session rejection
        sess2 = ops.create_session("Session 2", platform="local")
        act_diff_sess = ops.record_action(
            sess2.session_id,
            1,
            ActionCategory.RECON,
            "nmap",
            "scan",
            "Scan enemy-01 in sess2",
            target_id="enemy-01",
        )
        with pytest.raises(ValueError, match="Cross-session attachment rejected"):
            ops.attach_action_to_mission(act_diff_sess.id, m.mission_id)

        # Attack record cross-target rejection
        atk_diff_tgt = ops.record_attack(
            1,
            "enemy-02",
            "http",
            "sqli",
        )
        with pytest.raises(ValueError, match="Cross-target attachment rejected"):
            ops.attach_attack_to_mission(atk_diff_tgt.id, m.mission_id)

        # Defense record cross-target rejection
        def_diff_tgt = ops.record_defense(
            1,
            "own-01",
            "web",
            "patch",
        )
        with pytest.raises(ValueError, match="Cross-target attachment rejected"):
            ops.attach_defense_to_mission(def_diff_tgt.id, m.mission_id)

        # Flag record cross-target rejection
        flg_diff_tgt = ops.record_flag(
            1,
            "enemy-02",
            "curl",
            "flag{secret}",
        )
        with pytest.raises(ValueError, match="Cross-target attachment rejected"):
            ops.attach_flag_to_mission(flg_diff_tgt.id, m.mission_id)

        # SLA record cross-target rejection
        sla_diff_tgt = ops.record_sla(
            1,
            "enemy-02",
            "http",
            SlaStatus.OK,
        )
        with pytest.raises(ValueError, match="Cross-target attachment rejected"):
            ops.attach_sla_to_mission(sla_diff_tgt.id, m.mission_id)

        # Conflicting reassignment rejection for action, attack, defense, flag, sla
        # 1. Action
        act_valid = ops.record_action(
            session.session_id,
            1,
            ActionCategory.RECON,
            "nmap",
            "scan",
            "Valid scan",
            target_id="enemy-01",
            workflow_id=wf1.workflow_id,
        )
        assert ops.attach_action_to_mission(act_valid.id, m.mission_id) is True
        with pytest.raises(ValueError, match="Conflicting mission reassignment rejected"):
            ops.attach_action_to_mission(act_valid.id, m_second.mission_id)

        # 2. Attack
        atk_valid = ops.record_attack(
            1,
            "enemy-01",
            "http/8080",
            "sqli",
            workflow_id=wf1.workflow_id,
        )
        assert ops.attach_attack_to_mission(atk_valid.id, m.mission_id) is True
        with pytest.raises(ValueError, match="Conflicting mission reassignment rejected"):
            ops.attach_attack_to_mission(atk_valid.id, m_second.mission_id)

        # 3. Defense
        def_valid = ops.record_defense(
            1,
            "enemy-01",
            "http/8080",
            "patch",
            workflow_id=wf1.workflow_id,
        )
        assert ops.attach_defense_to_mission(def_valid.id, m.mission_id) is True
        with pytest.raises(ValueError, match="Conflicting mission reassignment rejected"):
            ops.attach_defense_to_mission(def_valid.id, m_second.mission_id)

        # 4. Flag
        flg_valid = ops.record_flag(
            1,
            "enemy-01",
            "curl",
            "flag{secret}",
            workflow_id=wf1.workflow_id,
        )
        assert ops.attach_flag_to_mission(flg_valid.id, m.mission_id) is True
        with pytest.raises(ValueError, match="Conflicting mission reassignment rejected"):
            ops.attach_flag_to_mission(flg_valid.id, m_second.mission_id)

        # 5. SLA
        sla_valid = ops.record_sla(
            1,
            "enemy-01",
            "http/8080",
            SlaStatus.OK,
            workflow_id=wf1.workflow_id,
        )
        assert ops.attach_sla_to_mission(sla_valid.id, m.mission_id) is True
        with pytest.raises(ValueError, match="Conflicting mission reassignment rejected"):
            ops.attach_sla_to_mission(sla_valid.id, m_second.mission_id)

        # Invariant: Never silently mutate workflow_id during attachment
        act_no_wf = ops.record_action(
            session.session_id,
            1,
            ActionCategory.RECON,
            "nmap",
            "scan",
            "Action with no workflow",
            target_id="enemy-01",
            workflow_id=None,
        )
        ops.attach_action_to_mission(act_no_wf.id, m.mission_id)
        act_reloaded = ops.get_action(act_no_wf.id)
        assert act_reloaded.mission_id == m.mission_id
        assert act_reloaded.workflow_id is None  # NOT silently mutated to m.workflow_id


def test_operational_records_with_mission_and_timeline():
    with tempfile.TemporaryDirectory() as d:
        _, _, ops, session, wf = _setup_service(d)

        m = ops.create_mission(
            wf.workflow_id,
            "enemy-01",
            8080,
            title="Investigate HTTP",
        )
        ops.start_mission(m.mission_id)

        # 1. Recon action
        act = ops.record_action(
            session.session_id,
            1,
            ActionCategory.RECON,
            "nmap",
            "port_scan",
            "Nmap scan 8080",
            target_id="enemy-01",
            workflow_id=wf.workflow_id,
            mission_id=m.mission_id,
        )
        assert act.mission_id == m.mission_id

        # 2. Attack record
        atk = ops.record_attack(
            1,
            "enemy-01",
            "http/8080",
            "path_traversal",
            workflow_id=wf.workflow_id,
            mission_id=m.mission_id,
            status=AttackStatus.SUCCESS,
        )
        assert atk.mission_id == m.mission_id

        # 3. Flag record (plaintext never stored)
        flg = ops.record_flag(
            1,
            "enemy-01",
            "curl",
            "flag{traversal_exploit_success}",
            workflow_id=wf.workflow_id,
            mission_id=m.mission_id,
            status=FlagStatus.VALIDATED,
        )
        assert flg.mission_id == m.mission_id
        assert "flag{traversal_exploit_success}" not in flg.fingerprint

        # 4. Defense record
        defn = ops.record_defense(
            1,
            "enemy-01",
            "http/8080",
            "input_validation",
            workflow_id=wf.workflow_id,
            mission_id=m.mission_id,
            status=DefenseStatus.COMPLETED,
        )
        assert defn.mission_id == m.mission_id

        # 5. Verification action linked to parent action
        verif = ops.record_action(
            session.session_id,
            1,
            ActionCategory.VERIFICATION,
            "http",
            "test_probe",
            "Probe path traversal endpoint",
            target_id="enemy-01",
            status="completed",
            workflow_id=wf.workflow_id,
            mission_id=m.mission_id,
            parent_action_id=act.id,
        )
        assert verif.mission_id == m.mission_id
        assert verif.parent_action_id == act.id

        # 6. SLA observation
        sla = ops.record_sla(
            1,
            "enemy-01",
            "http/8080",
            SlaStatus.OK,
            latency_ms=12.5,
            workflow_id=wf.workflow_id,
            mission_id=m.mission_id,
        )
        assert sla.mission_id == m.mission_id

        # Timeline check: all 6 entries should appear chronologically
        entries = ops.get_mission_timeline(m.mission_id)
        assert len(entries) == 6
        cats = [e.category.upper() for e in entries]
        assert "RECON" in cats
        assert "ATTACK" in cats
        assert "FLAG" in cats
        assert "DEFENSE" in cats
        assert "VERIFICATION" in cats
        assert "SLA" in cats

        # Verify list filtering by mission_id
        assert len(ops.list_actions(mission_id=m.mission_id)) == 2
        assert len(ops.list_attacks(mission_id=m.mission_id)) == 1
        assert len(ops.list_defenses(mission_id=m.mission_id)) == 1
        assert len(ops.list_flags(mission_id=m.mission_id)) == 1
        assert len(ops.list_sla(mission_id=m.mission_id)) == 1


def test_mission_persistence_and_database_migration():
    with tempfile.TemporaryDirectory() as d:
        db_path, _, ops, session, wf = _setup_service(d)

        m = ops.create_mission(
            workflow_id=wf.workflow_id,
            target_id="enemy-01",
            service_port=8080,
            title="Persistent Mission",
            objective="Survive restart",
        )
        ops.start_mission(m.mission_id)
        ops.complete_mission(m.mission_id, notes="Finished before reload")

        # Reopen service on the same SQLite file
        targets_new = TargetService(db_path)
        ops_new = OperationService(db_path, target_service=targets_new)

        reloaded_m = ops_new.get_mission(m.mission_id)
        assert reloaded_m is not None
        assert reloaded_m.title == "Persistent Mission"
        assert reloaded_m.status == MissionStatus.COMPLETED
        assert reloaded_m.notes == "Finished before reload"
        assert reloaded_m.completed_at is not None
