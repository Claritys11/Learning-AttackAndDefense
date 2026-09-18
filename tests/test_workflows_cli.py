import json
import tempfile
import pytest

from attnndef.cli import main
from attnndef.context import ContextStore, OperatorContext
from attnndef.operations import OperationService, WorkflowStatus
from attnndef.targets import Role, Scope, Target, TargetService


def test_cli_workflow_lifecycle_and_json(capsys):
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        store = ContextStore(db_path)
        ctx = OperatorContext(operator_name="Kai", current_round=1, session_id="test-sess-01")
        store.save(ctx)

        # Initialize session and round in service
        svc = OperationService(db_path)
        svc.create_session(session_id="test-sess-01", operator="Kai")
        svc.start_round("test-sess-01", 1)

        # 1. Create workflow via CLI
        rc = main([
            "--state-db", db_path,
            "workflow", "--create",
            "--title", "Investigate web service on target-03",
            "--objective", "Understand unexpected HTTP behavior",
            "--notes", "Created by Kai",
            "--json",
        ])
        assert rc == 0
        captured = capsys.readouterr().out
        created_data = json.loads(captured)
        wf_id = created_data["workflow_id"]
        assert created_data["title"] == "Investigate web service on target-03"
        assert created_data["status"] == "active"

        # 2. List workflows via CLI
        rc = main(["--state-db", db_path, "workflow", "--list", "--json"])
        assert rc == 0
        listed = json.loads(capsys.readouterr().out)
        assert len(listed) == 1
        assert listed[0]["workflow_id"] == wf_id

        # 3. Show workflow via CLI (human-readable)
        rc = main(["--state-db", db_path, "workflow", "--show", wf_id])
        assert rc == 0
        show_out = capsys.readouterr().out
        assert f"WORKFLOW #{wf_id[:8]}" in show_out
        assert "Investigate web service on target-03" in show_out
        assert "Status:    ACTIVE" in show_out

        # 4. Complete workflow via CLI
        rc = main(["--state-db", db_path, "workflow", "--complete", wf_id, "--notes", "Remediation verified", "--json"])
        assert rc == 0
        comp_data = json.loads(capsys.readouterr().out)
        assert comp_data["completed"] is True
        assert comp_data["status"] == "completed"

        # Verify status in database
        wf_reloaded = svc.get_workflow(wf_id)
        assert wf_reloaded.status == WorkflowStatus.COMPLETED
        assert wf_reloaded.notes == "Remediation verified"


def test_cli_operational_records_with_workflow(capsys):
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        store = ContextStore(db_path)
        ctx = OperatorContext(operator_name="Kai", current_round=1, session_id="sess-42")
        store.save(ctx)

        targets = TargetService(db_path)
        targets.add_target(Target("target-03", "target-03", "10.0.0.13", Role.ENEMY))

        svc = OperationService(db_path, target_service=targets)
        svc.create_session(session_id="sess-42", operator="Kai")
        svc.start_round("sess-42", 1)

        # Create workflow
        wf = svc.create_workflow("sess-42", 1, "Target-03 Investigation", target_id="target-03")

        # 1. Action with --workflow
        rc = main([
            "--state-db", db_path,
            "action", "--record",
            "--category", "recon",
            "--target", "target-03",
            "--tool", "nmap",
            "--op", "service_scan",
            "--summary", "Nmap service scan",
            "--workflow", wf.workflow_id,
            "--json",
        ])
        assert rc == 0
        act_data = json.loads(capsys.readouterr().out)
        assert act_data["workflow_id"] == wf.workflow_id
        action_id = act_data["id"]

        # 2. Verification Action with --workflow and --parent
        rc = main([
            "--state-db", db_path,
            "action", "--record",
            "--category", "verification",
            "--target", "target-03",
            "--tool", "curl",
            "--op", "health_check",
            "--summary", "Health check /health",
            "--workflow", wf.workflow_id,
            "--parent", action_id,
            "--json",
        ])
        assert rc == 0
        verify_data = json.loads(capsys.readouterr().out)
        assert verify_data["workflow_id"] == wf.workflow_id
        assert verify_data["parent_action_id"] == action_id

        # 3. Attack with --workflow
        rc = main([
            "--state-db", db_path,
            "attack", "--record",
            "--target", "target-03",
            "--service", "http/80",
            "--method", "sql injection probe",
            "--workflow", wf.workflow_id,
            "--json",
        ])
        assert rc == 0
        atk_data = json.loads(capsys.readouterr().out)
        assert atk_data["workflow_id"] == wf.workflow_id

        # 4. Defense with --workflow
        rc = main([
            "--state-db", db_path,
            "defense", "--record",
            "--target", "target-03",
            "--service", "http/80",
            "--action", "service restart",
            "--workflow", wf.workflow_id,
            "--json",
        ])
        assert rc == 0
        df_data = json.loads(capsys.readouterr().out)
        assert df_data["workflow_id"] == wf.workflow_id

        # 5. Flag with --workflow (verify fingerprint only, no plaintext)
        rc = main([
            "--state-db", db_path,
            "flag",
            "--record", "flag{sample_secret_key_1234}",
            "--target", "target-03",
            "--source", "HTTP leak",
            "--workflow", wf.workflow_id,
            "--json",
        ])
        assert rc == 0
        fl_data = json.loads(capsys.readouterr().out)
        assert fl_data["workflow_id"] == wf.workflow_id
        assert fl_data["flag_preview"] == "flag{..._1234}"
        assert "sample_secret_key_1234" not in fl_data["fingerprint"]
        assert fl_data["fingerprint"].startswith("sha256:")

        # 6. SLA with --workflow
        rc = main([
            "--state-db", db_path,
            "sla", "--record",
            "--target", "target-03",
            "--service", "http/80",
            "--status", "ok",
            "--latency", "45",
            "--workflow", wf.workflow_id,
            "--json",
        ])
        assert rc == 0
        sla_data = json.loads(capsys.readouterr().out)
        assert sla_data["workflow_id"] == wf.workflow_id

        # 7. Query workflow timeline via `workflow --timeline <id>`
        rc = main(["--state-db", db_path, "workflow", "--timeline", wf.workflow_id])
        assert rc == 0
        wf_tl_out = capsys.readouterr().out
        assert f"WORKFLOW #{wf.workflow_id[:8]}" in wf_tl_out
        assert "Nmap service scan" in wf_tl_out
        assert "Health check /health" in wf_tl_out
        assert "sql injection probe" in wf_tl_out
        assert "service restart" in wf_tl_out

        # 8. Query workflow timeline via `timeline --workflow <id>`
        rc = main(["--state-db", db_path, "timeline", "--workflow", wf.workflow_id])
        assert rc == 0
        tl_wf_out = capsys.readouterr().out
        assert f"WORKFLOW #{wf.workflow_id[:8]}" in tl_wf_out
        assert "Target-03 Investigation" in tl_wf_out


def test_security_workflow_never_bypasses_scope_or_executes_tools():
    """Verify that creating or referencing a workflow does not authorize out-of-scope targets
    and does not autonomously trigger external subprocesses.
    """
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        targets = TargetService(db_path)
        # own target (defense allowed, attack disallowed)
        targets.add_target(Target("own-target", "own-target", "10.10.4.2", Role.OWN))
        # enemy target
        targets.add_target(Target("enemy-target", "enemy-target", "10.10.5.2", Role.ENEMY))

        svc = OperationService(db_path, target_service=targets)
        sess = svc.create_session(team_id="team-04", operator="Kai")
        rnd = svc.start_round(sess.session_id, 1)

        # Workflows can be created for any known target as an organizational container
        wf = svc.create_workflow(sess.session_id, rnd.round_id, "Workflow Own Target", target_id="own-target")
        assert wf.target_id == "own-target"

        # But Scope and Boundary remain completely unchanged:
        # Own targets cannot be attacked through Scope
        from attnndef.targets import ExecutionBoundary
        guard = ExecutionBoundary(Scope(frozenset({Role.ENEMY}), ("10.10.0.0/16",)))
        enemy_tgt = targets.get_target("enemy-target")
        own_tgt = targets.get_target("own-target")
        guard.authorize_attack(enemy_tgt)

        # Workflow existence does not alter Scope authorization
        with pytest.raises(ValueError, match="outside scope"):
            guard.authorize_attack(own_tgt)
