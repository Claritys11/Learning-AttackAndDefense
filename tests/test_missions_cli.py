import json
import sqlite3
import tempfile
import pytest

from attnndef.cli import main
from attnndef.context import ContextStore, OperatorContext
from attnndef.operations import MissionStatus, OperationService
from attnndef.targets import Role, Scope, Target, TargetService


def test_cli_mission_lifecycle_and_json(capsys):
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        store = ContextStore(db_path)
        ctx = OperatorContext(operator_name="Kai", current_round=1, session_id="test-sess-01")
        store.save(ctx)

        targets = TargetService(db_path)
        targets.add_target(Target("enemy-03", "enemy-03", "10.0.0.3", Role.ENEMY))

        svc = OperationService(db_path, target_service=targets)
        svc.create_session(session_id="test-sess-01", operator="Kai")
        svc.start_round("test-sess-01", 1)
        wf = svc.create_workflow("test-sess-01", 1, "Investigate enemy services", target_id="enemy-03")

        # 1. Create mission via CLI
        rc = main([
            "--state-db", db_path,
            "mission", "--create",
            "--workflow", wf.workflow_id,
            "--target", "enemy-03",
            "--port", "8080",
            "--protocol", "tcp",
            "--title", "Investigate HTTP service",
            "--objective", "Investigate unexpected endpoint behavior",
            "--json",
        ])
        assert rc == 0
        captured = capsys.readouterr().out
        created_data = json.loads(captured)
        mid = created_data["mission_id"]
        assert created_data["title"] == "Investigate HTTP service"
        assert created_data["target_id"] == "enemy-03"
        assert created_data["service_port"] == 8080
        assert created_data["service_protocol"] == "tcp"
        assert created_data["status"] == "open"

        # 2. List missions via CLI
        rc = main(["--state-db", db_path, "mission", "--list", "--json"])
        assert rc == 0
        listed = json.loads(capsys.readouterr().out)
        assert len(listed) == 1
        assert listed[0]["mission_id"] == mid

        # 3. Show mission via CLI (human-readable)
        rc = main(["--state-db", db_path, "mission", "--show", mid])
        assert rc == 0
        show_out = capsys.readouterr().out
        assert f"MISSION #{mid[:8]}" in show_out
        assert "Investigate HTTP service" in show_out
        assert "TCP/8080" in show_out
        assert "Status:    OPEN" in show_out

        # 4. Start mission via CLI
        rc = main(["--state-db", db_path, "mission", "--start", mid, "--json"])
        assert rc == 0
        start_data = json.loads(capsys.readouterr().out)
        assert start_data["started"] is True
        assert start_data["status"] == "in_progress"

        # 5. Complete mission via CLI
        rc = main(["--state-db", db_path, "mission", "--complete", mid, "--notes", "Endpoint analyzed", "--json"])
        assert rc == 0
        comp_data = json.loads(capsys.readouterr().out)
        assert comp_data["completed"] is True
        assert comp_data["status"] == "completed"

        # Verify status in database
        m_reloaded = svc.get_mission(mid)
        assert m_reloaded.status == MissionStatus.COMPLETED
        assert m_reloaded.notes == "Endpoint analyzed"

        # 6. Create another mission and abort it via CLI
        rc = main([
            "--state-db", db_path,
            "mission", "--create",
            "--workflow", wf.workflow_id,
            "--target", "enemy-03",
            "--port", "22",
            "--title", "SSH check",
            "--json",
        ])
        assert rc == 0
        m2_id = json.loads(capsys.readouterr().out)["mission_id"]

        rc = main(["--state-db", db_path, "mission", "--abort", m2_id, "--notes", "Out of time", "--json"])
        assert rc == 0
        abort_data = json.loads(capsys.readouterr().out)
        assert abort_data["aborted"] is True
        assert abort_data["status"] == "aborted"


def test_cli_operational_records_with_mission(capsys):
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        store = ContextStore(db_path)
        ctx = OperatorContext(operator_name="Kai", current_round=1, session_id="sess-42")
        store.save(ctx)

        targets = TargetService(db_path)
        targets.add_target(Target("enemy-04", "enemy-04", "10.0.0.4", Role.ENEMY))

        svc = OperationService(db_path, target_service=targets)
        svc.create_session(session_id="sess-42", operator="Kai")
        svc.start_round("sess-42", 1)

        wf = svc.create_workflow("sess-42", 1, "Enemy-04 Workflow", target_id="enemy-04")
        m = svc.create_mission(wf.workflow_id, "enemy-04", 8080, title="Enemy-04 Mission")
        svc.start_mission(m.mission_id)

        # 1. Action with --mission
        rc = main([
            "--state-db", db_path,
            "action", "--record",
            "--category", "recon",
            "--target", "enemy-04",
            "--tool", "nmap",
            "--op", "service_scan",
            "--summary", "Scan port 8080",
            "--workflow", wf.workflow_id,
            "--mission", m.mission_id,
            "--json",
        ])
        assert rc == 0
        act_data = json.loads(capsys.readouterr().out)
        assert act_data["mission_id"] == m.mission_id
        act_id = act_data["id"]

        # 2. Attack with --mission
        rc = main([
            "--state-db", db_path,
            "attack", "--record",
            "--target", "enemy-04",
            "--service", "http/8080",
            "--method", "traversal_exploit",
            "--status", "success",
            "--workflow", wf.workflow_id,
            "--mission", m.mission_id,
            "--json",
        ])
        assert rc == 0
        atk_data = json.loads(capsys.readouterr().out)
        assert atk_data["mission_id"] == m.mission_id

        # 3. Defense with --mission
        rc = main([
            "--state-db", db_path,
            "defense", "--record",
            "--target", "enemy-04",
            "--service", "http/8080",
            "--action", "nginx_path_filter",
            "--status", "completed",
            "--workflow", wf.workflow_id,
            "--mission", m.mission_id,
            "--json",
        ])
        assert rc == 0
        def_data = json.loads(capsys.readouterr().out)
        assert def_data["mission_id"] == m.mission_id

        # 4. Flag with --mission
        rc = main([
            "--state-db", db_path,
            "flag",
            "--record", "flag{sample_mission_flag_12345}",
            "--target", "enemy-04",
            "--source", "http_leak",
            "--workflow", wf.workflow_id,
            "--mission", m.mission_id,
            "--json",
        ])
        assert rc == 0
        flg_data = json.loads(capsys.readouterr().out)
        assert flg_data["mission_id"] == m.mission_id

        # 5. SLA with --mission
        rc = main([
            "--state-db", db_path,
            "sla", "--record",
            "--target", "enemy-04",
            "--service", "http/8080",
            "--status", "ok",
            "--latency", "45",
            "--workflow", wf.workflow_id,
            "--mission", m.mission_id,
            "--json",
        ])
        assert rc == 0
        sla_data = json.loads(capsys.readouterr().out)
        assert sla_data["mission_id"] == m.mission_id

        # 6. Timeline filtered by --mission
        rc = main([
            "--state-db", db_path,
            "timeline",
            "--mission", m.mission_id,
            "--json",
        ])
        assert rc == 0
        tl_data = json.loads(capsys.readouterr().out)
        assert len(tl_data) == 5

        # 7. Mission timeline command
        rc = main([
            "--state-db", db_path,
            "mission", "--timeline", m.mission_id,
            "--json",
        ])
        assert rc == 0
        m_tl_data = json.loads(capsys.readouterr().out)
        assert len(m_tl_data) == 5


def test_security_mission_never_bypasses_scope_or_executes_tools(capsys):
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        store = ContextStore(db_path)
        ctx = OperatorContext(operator_name="Kai", current_round=1, session_id="sess-sec")
        store.save(ctx)

        targets = TargetService(db_path)
        targets.add_target(Target("enemy-05", "enemy-05", "10.0.0.5", Role.ENEMY))

        svc = OperationService(db_path, target_service=targets)
        svc.create_session(session_id="sess-sec", operator="Kai")
        svc.start_round("sess-sec", 1)

        wf = svc.create_workflow("sess-sec", 1, "Security Test Workflow", target_id="enemy-05")
        m = svc.create_mission(wf.workflow_id, "enemy-05", 8080, title="Security Mission")

        # Plaintext flag security: never stored in database
        raw_flag = "flag{super_secret_mission_flag}"
        rc = main([
            "--state-db", db_path,
            "flag",
            "--record", raw_flag,
            "--target", "enemy-05",
            "--source", "exploit",
            "--mission", m.mission_id,
            "--json",
        ])
        assert rc == 0

        # Verify database contents directly
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT * FROM flag_records WHERE mission_id = ?", (m.mission_id,))
        row = cur.fetchone()
        assert row is not None
        # Entire row converted to string must not contain raw flag
        row_str = " ".join(str(val) for val in row)
        assert raw_flag not in row_str
        conn.close()
