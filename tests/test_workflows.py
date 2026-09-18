import tempfile
import sqlite3
import pytest

from attnndef.targets import Role, Target, TargetService
from attnndef.operations import (
    ActionCategory,
    AttackStatus,
    DefenseStatus,
    FlagStatus,
    OperationService,
    RoundStatus,
    SessionStatus,
    SlaStatus,
    WorkflowRun,
    WorkflowStatus,
    make_flag_fingerprint,
)


def test_workflow_lifecycle_and_transitions():
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        svc = OperationService(db_path)
        session = svc.create_session(team_id="team-04", operator="Kai")
        rnd = svc.start_round(session.session_id, 1)

        # Create workflow
        wf = svc.create_workflow(
            session_id=session.session_id,
            round_id=rnd.round_id,
            title="Investigate web service",
            objective="Analyze unusual HTTP 500 errors",
            notes="Initial operator note",
        )
        assert wf.workflow_id
        assert wf.title == "Investigate web service"
        assert wf.objective == "Analyze unusual HTTP 500 errors"
        assert wf.status == WorkflowStatus.ACTIVE
        assert wf.completed_at is None

        # Get workflow
        fetched = svc.get_workflow(wf.workflow_id)
        assert fetched is not None
        assert fetched.workflow_id == wf.workflow_id
        assert fetched.title == wf.title

        # List workflows
        wfs = svc.list_workflows(session_id=session.session_id)
        assert len(wfs) == 1
        assert wfs[0].workflow_id == wf.workflow_id

        # Complete workflow
        completed = svc.complete_workflow(wf.workflow_id, notes="Resolved via nginx fix")
        assert completed is True
        wf_done = svc.get_workflow(wf.workflow_id)
        assert wf_done.status == WorkflowStatus.COMPLETED
        assert wf_done.completed_at is not None
        assert wf_done.notes == "Resolved via nginx fix"

        # Invalid transition: cannot complete or abort an already completed workflow
        with pytest.raises(ValueError, match="Cannot complete workflow in state completed"):
            svc.complete_workflow(wf.workflow_id)
        with pytest.raises(ValueError, match="Cannot abort workflow in state completed"):
            svc.abort_workflow(wf.workflow_id)

        # Create second workflow and abort it
        wf2 = svc.create_workflow(
            session_id=session.session_id,
            round_id=rnd.round_id,
            title="Secondary check",
        )
        assert wf2.status == WorkflowStatus.ACTIVE
        aborted = svc.abort_workflow(wf2.workflow_id, notes="Operator aborted: out of time")
        assert aborted is True
        wf2_aborted = svc.get_workflow(wf2.workflow_id)
        assert wf2_aborted.status == WorkflowStatus.ABORTED
        assert wf2_aborted.completed_at is not None

        # Filter by status
        active_list = svc.list_workflows(status=WorkflowStatus.ACTIVE)
        assert len(active_list) == 0
        completed_list = svc.list_workflows(status=WorkflowStatus.COMPLETED)
        assert len(completed_list) == 1
        aborted_list = svc.list_workflows(status=WorkflowStatus.ABORTED)
        assert len(aborted_list) == 1


def test_workflow_target_validation():
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        targets = TargetService(db_path)
        targets.add_target(Target("target-01", "target-01", "10.0.0.1", Role.ENEMY))
        svc = OperationService(db_path, target_service=targets)

        session = svc.create_session(team_id="team-04", operator="Kai")
        rnd = svc.start_round(session.session_id, 1)

        # Valid target succeeds
        wf = svc.create_workflow(
            session_id=session.session_id,
            round_id=rnd.round_id,
            title="Scan target 1",
            target_id="target-01",
        )
        assert wf.target_id == "target-01"

        # Invalid target fails validation
        with pytest.raises(ValueError, match="target not found in registry: non-existent-target"):
            svc.create_workflow(
                session_id=session.session_id,
                round_id=rnd.round_id,
                title="Scan invalid",
                target_id="non-existent-target",
            )


def test_workflow_attachments_and_cross_session_rejection():
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        svc = OperationService(db_path)

        # Session 1
        sess1 = svc.create_session(team_id="team-04", operator="Kai")
        rnd1 = svc.start_round(sess1.session_id, 1)
        wf1 = svc.create_workflow(sess1.session_id, rnd1.round_id, "Workflow Session 1")

        # Session 2
        sess2 = svc.create_session(team_id="team-04", operator="Kai")
        rnd2 = svc.start_round(sess2.session_id, 2)
        wf2 = svc.create_workflow(sess2.session_id, rnd2.round_id, "Workflow Session 2")

        # 1. Attach action
        act1 = svc.record_action(sess1.session_id, rnd1.round_id, ActionCategory.RECON, "nmap", "scan", "Port sweep")
        assert act1.workflow_id is None
        assert svc.attach_action_to_workflow(act1.id, wf1.workflow_id) is True
        act1_attached = svc.get_action(act1.id)
        assert act1_attached.workflow_id == wf1.workflow_id

        # Cross-session rejection: attach action from sess1 to wf2 (sess2)
        with pytest.raises(ValueError, match="Cross-session attachment rejected"):
            svc.attach_action_to_workflow(act1.id, wf2.workflow_id)

        # 2. Attach attack
        atk1 = svc.record_attack(rnd1.round_id, "target-01", "http/80", "sql injection")
        assert svc.attach_attack_to_workflow(atk1.id, wf1.workflow_id) is True
        atk1_attached = svc.get_attack(atk1.id)
        assert atk1_attached.workflow_id == wf1.workflow_id

        # Cross-session rejection: attack from rnd1 (sess1) to wf2 (sess2)
        with pytest.raises(ValueError, match="Cross-session attachment rejected"):
            svc.attach_attack_to_workflow(atk1.id, wf2.workflow_id)

        # 3. Attach defense
        df1 = svc.record_defense(rnd1.round_id, "target-01", "http/80", "add input validation")
        assert svc.attach_defense_to_workflow(df1.id, wf1.workflow_id) is True
        df1_attached = svc.get_defense(df1.id)
        assert df1_attached.workflow_id == wf1.workflow_id

        with pytest.raises(ValueError, match="Cross-session attachment rejected"):
            svc.attach_defense_to_workflow(df1.id, wf2.workflow_id)

        # 4. Attach flag
        fl1 = svc.record_flag(rnd1.round_id, "target-01", "manual", "flag{abc12345}")
        assert svc.attach_flag_to_workflow(fl1.id, wf1.workflow_id) is True
        fl1_attached = svc.get_flag(fl1.id)
        assert fl1_attached.workflow_id == wf1.workflow_id

        with pytest.raises(ValueError, match="Cross-session attachment rejected"):
            svc.attach_flag_to_workflow(fl1.id, wf2.workflow_id)

        # 5. Attach SLA
        sla1 = svc.record_sla(rnd1.round_id, "target-01", "http/80", SlaStatus.OK)
        assert svc.attach_sla_to_workflow(sla1.id, wf1.workflow_id) is True
        sla1_attached = svc.get_sla(sla1.id)
        assert sla1_attached.workflow_id == wf1.workflow_id

        with pytest.raises(ValueError, match="Cross-session attachment rejected"):
            svc.attach_sla_to_workflow(sla1.id, wf2.workflow_id)

        # 6. Reject non-existent workflow or record
        with pytest.raises(ValueError, match="Workflow not found"):
            svc.attach_action_to_workflow(act1.id, "non-existent-wf")
        with pytest.raises(ValueError, match="Action not found"):
            svc.attach_action_to_workflow("non-existent-action", wf1.workflow_id)
        with pytest.raises(ValueError, match="Attack not found"):
            svc.attach_attack_to_workflow("non-existent-atk", wf1.workflow_id)
        with pytest.raises(ValueError, match="Defense not found"):
            svc.attach_defense_to_workflow("non-existent-df", wf1.workflow_id)
        with pytest.raises(ValueError, match="Flag record not found"):
            svc.attach_flag_to_workflow("non-existent-fl", wf1.workflow_id)
        with pytest.raises(ValueError, match="SLA observation not found"):
            svc.attach_sla_to_workflow("non-existent-sla", wf1.workflow_id)


def test_verification_workflow_and_parent_action_linking():
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        svc = OperationService(db_path)
        session = svc.create_session(team_id="team-04", operator="Kai")
        rnd = svc.start_round(session.session_id, 1)
        wf = svc.create_workflow(session.session_id, rnd.round_id, "Patch and verify web service")

        # 1. Defense Action: restart service / apply patch
        defense_act = svc.record_action(
            session.session_id,
            rnd.round_id,
            ActionCategory.DEFENSE,
            "patcher",
            "apply",
            "Patch SQL injection vulnerability",
            workflow_id=wf.workflow_id,
        )
        assert defense_act.parent_action_id is None
        assert defense_act.workflow_id == wf.workflow_id

        # 2. Verification Action explicitly linked to parent defense action
        verify_act = svc.record_action(
            session.session_id,
            rnd.round_id,
            ActionCategory.VERIFICATION,
            "curl",
            "health_check",
            "HTTP GET /health verification",
            workflow_id=wf.workflow_id,
            parent_action_id=defense_act.id,
            tool_execution_id="exec-12345",
        )
        assert verify_act.parent_action_id == defense_act.id
        assert verify_act.tool_execution_id == "exec-12345"
        assert verify_act.workflow_id == wf.workflow_id

        # Retrieve and verify persistence of relationship
        fetched = svc.get_action(verify_act.id)
        assert fetched is not None
        assert fetched.parent_action_id == defense_act.id
        assert fetched.tool_execution_id == "exec-12345"

        # Reject invalid parent action
        with pytest.raises(ValueError, match="Parent action not found"):
            svc.record_action(
                session.session_id,
                rnd.round_id,
                ActionCategory.VERIFICATION,
                "curl",
                "health_check",
                "Invalid parent",
                parent_action_id="non-existent-parent",
            )


def test_workflow_timeline_deterministic_chronological_order():
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        svc = OperationService(db_path)
        session = svc.create_session(team_id="team-04", operator="Kai")
        rnd = svc.start_round(session.session_id, 1)

        wf = svc.create_workflow(session.session_id, rnd.round_id, "Incident Response Workflow", target_id="target-03")

        # Empty workflow timeline
        empty_entries = svc.get_workflow_timeline(wf.workflow_id)
        assert empty_entries == []

        # Create records with increasing timestamps
        t0 = 1000.0
        # 1. Recon (t0 + 10)
        svc.record_action(
            session.session_id, rnd.round_id, ActionCategory.RECON, "nmap", "scan", "Nmap service scan",
            target_id="target-03", timestamp=t0 + 10, workflow_id=wf.workflow_id
        )
        # 2. HTTP GET / (t0 + 20)
        svc.record_action(
            session.session_id, rnd.round_id, ActionCategory.RECON, "curl", "get", "HTTP GET /",
            target_id="target-03", timestamp=t0 + 20, workflow_id=wf.workflow_id
        )
        # 3. Verification /health (t0 + 30)
        svc.record_action(
            session.session_id, rnd.round_id, ActionCategory.VERIFICATION, "curl", "health", "Health check",
            target_id="target-03", timestamp=t0 + 30, workflow_id=wf.workflow_id
        )
        # 4. Defense service restart (t0 + 40)
        svc.record_defense(
            rnd.round_id, "target-03", "http/80", "Service restart",
            status=DefenseStatus.COMPLETED, started_at=t0 + 40, workflow_id=wf.workflow_id
        )
        # 5. Verification /health after restart (t0 + 50)
        svc.record_action(
            session.session_id, rnd.round_id, ActionCategory.VERIFICATION, "curl", "health", "Health check after restart",
            target_id="target-03", timestamp=t0 + 50, workflow_id=wf.workflow_id
        )

        timeline = svc.get_workflow_timeline(wf.workflow_id)
        assert len(timeline) == 5

        # Must be chronologically ascending: earliest first
        timestamps = [e.timestamp for e in timeline]
        assert timestamps == sorted(timestamps)
        assert timeline[0].category == "RECON"
        assert timeline[0].title == "nmap scan: Nmap service scan"
        assert timeline[1].title == "curl get: HTTP GET /"
        assert timeline[2].category == "VERIFICATION"
        assert timeline[3].category == "DEFENSE"
        assert timeline[4].category == "VERIFICATION"


def test_database_persistence_and_reload():
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        svc = OperationService(db_path)
        session = svc.create_session(team_id="team-04", operator="Kai")
        rnd = svc.start_round(session.session_id, 1)

        wf = svc.create_workflow(session.session_id, rnd.round_id, "Persistent Workflow", objective="Survive restarts")
        act = svc.record_action(
            session.session_id,
            rnd.round_id,
            ActionCategory.DEFENSE,
            "sys",
            "restart",
            "Restarted service",
            workflow_id=wf.workflow_id,
            tool_execution_id="exec-9999",
        )
        atk = svc.record_attack(rnd.round_id, "target-01", "http/80", "exploit", workflow_id=wf.workflow_id)

        # Close and instantiate new OperationService pointing to same db_path
        svc2 = OperationService(db_path)
        reloaded_wf = svc2.get_workflow(wf.workflow_id)
        assert reloaded_wf is not None
        assert reloaded_wf.title == "Persistent Workflow"
        assert reloaded_wf.objective == "Survive restarts"

        reloaded_act = svc2.get_action(act.id)
        assert reloaded_act is not None
        assert reloaded_act.workflow_id == wf.workflow_id
        assert reloaded_act.tool_execution_id == "exec-9999"

        reloaded_atk = svc2.get_attack(atk.id)
        assert reloaded_atk is not None
        assert reloaded_atk.workflow_id == wf.workflow_id


def test_backward_compatibility_migration():
    """Verify that opening an existing SQLite database lacking workflow tables and columns
    automatically migrates cleanly without data loss.
    """
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/legacy.db"
        # Create legacy schema without operational_workflows and without workflow_id columns
        conn = sqlite3.connect(db_path)
        conn.executescript("""
        CREATE TABLE operational_sessions (
            session_id TEXT PRIMARY KEY, competition TEXT NOT NULL, platform TEXT NOT NULL,
            team_id TEXT NOT NULL, operator TEXT NOT NULL, vpn_interface TEXT NOT NULL,
            own_ip TEXT NOT NULL, enemy_subnet TEXT NOT NULL, started_at REAL NOT NULL,
            ended_at REAL, status TEXT NOT NULL
        );
        CREATE TABLE operational_rounds (
            round_id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, round_number INTEGER NOT NULL,
            started_at REAL NOT NULL, ended_at REAL, status TEXT NOT NULL
        );
        CREATE TABLE operational_ticks (
            id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, round_id INTEGER NOT NULL,
            tick_number INTEGER NOT NULL, observed_at REAL NOT NULL, status TEXT NOT NULL
        );
        CREATE TABLE operator_actions (
            id TEXT PRIMARY KEY, session_id TEXT NOT NULL, round_id INTEGER NOT NULL,
            timestamp REAL NOT NULL, category TEXT NOT NULL, target_id TEXT, tool TEXT NOT NULL,
            operation TEXT NOT NULL, summary TEXT NOT NULL, status TEXT NOT NULL,
            evidence_id TEXT, details TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE attack_records (
            id TEXT PRIMARY KEY, round_id INTEGER NOT NULL, target_id TEXT NOT NULL,
            service TEXT NOT NULL, method TEXT NOT NULL, status TEXT NOT NULL,
            started_at REAL NOT NULL, completed_at REAL, notes TEXT NOT NULL, evidence_id TEXT
        );
        CREATE TABLE defense_records (
            id TEXT PRIMARY KEY, round_id INTEGER NOT NULL, target_id TEXT NOT NULL,
            service TEXT NOT NULL, action TEXT NOT NULL, status TEXT NOT NULL,
            started_at REAL NOT NULL, completed_at REAL, notes TEXT NOT NULL, evidence_id TEXT
        );
        CREATE TABLE flag_records (
            id TEXT PRIMARY KEY, round_id INTEGER NOT NULL, target_id TEXT NOT NULL,
            source TEXT NOT NULL, observed_at REAL NOT NULL, status TEXT NOT NULL,
            fingerprint TEXT NOT NULL, flag_preview TEXT NOT NULL, notes TEXT NOT NULL, evidence_id TEXT
        );
        CREATE TABLE sla_observations (
            id TEXT PRIMARY KEY, round_id INTEGER NOT NULL, target_id TEXT NOT NULL,
            service TEXT NOT NULL, observed_at REAL NOT NULL, status TEXT NOT NULL,
            latency_ms REAL, source TEXT NOT NULL, details TEXT NOT NULL DEFAULT '{}'
        );
        INSERT INTO operational_sessions VALUES ('s1', 'Grand Final', 'plat', 't1', 'Kai', 'wg0', '10.0.0.2', '10.0.0.0/16', 100.0, NULL, 'active');
        INSERT INTO operational_rounds VALUES (1, 's1', 1, 100.0, NULL, 'active');
        INSERT INTO operator_actions VALUES ('a1', 's1', 1, 105.0, 'recon', 't1', 'nmap', 'scan', 'Legacy action', 'completed', NULL, '{}');
        """)
        conn.commit()
        conn.close()

        # Opening legacy db with OperationService must perform migration without error
        svc = OperationService(db_path)
        legacy_act = svc.get_action("a1")
        assert legacy_act is not None
        assert legacy_act.summary == "Legacy action"
        assert legacy_act.workflow_id is None

        # Now create workflow and attach legacy action
        wf = svc.create_workflow("s1", 1, "Migrated Workflow")
        assert svc.attach_action_to_workflow("a1", wf.workflow_id) is True
        migrated_act = svc.get_action("a1")
        assert migrated_act.workflow_id == wf.workflow_id
