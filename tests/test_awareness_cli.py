import json
import tempfile
import time
import pytest

from attnndef.cli import main
from attnndef.context import ContextStore, OperatorContext
from attnndef.core.models import Evidence
from attnndef.io.sink import LocalSink
from attnndef.operations import ActionCategory, OperationService, SlaStatus
from attnndef.targets import Observation, Role, Service, Target, TargetService


def _setup_cli_env(tmp_dir: str):
    db_path = f"{tmp_dir}/state.db"
    sink_path = f"{tmp_dir}/sink.jsonl"
    store = ContextStore(db_path)
    store.save(OperatorContext(operator_name="Kai", current_round=1, session_id="cli-sess"))

    targets = TargetService(db_path)
    targets.add_target(Target("enemy-03", "enemy-03", "10.0.0.3", Role.ENEMY))

    obs = targets.record_observation(
        Observation(
            id=None,
            target_id="enemy-03",
            observed_at=time.time(),
            services=(Service(port=8080, protocol="tcp", name="http", version="Apache/2.4"),),
        )
    )

    ops = OperationService(db_path, target_service=targets)
    ops.create_session("cli-sess", operator="Kai")
    ops.start_round("cli-sess", 1)

    wf = ops.create_workflow("cli-sess", 1, "CLI Workflow", target_id="enemy-03")
    m = ops.create_mission(
        workflow_id=wf.workflow_id,
        target_id="enemy-03",
        service_port=8080,
        title="CLI Mission",
        objective="Test awareness CLI",
        initial_observation_id=obs.id,
    )

    sink = LocalSink(sink_path)
    ev = Evidence(
        id="ev-cli-001",
        ts=time.time(),
        kind="tool_http",
        target_id="enemy-03",
        ok=True,
        payload={"url": "http://10.0.0.3:8080/", "status_code": 200},
    )
    sink.write(ev)

    ops.record_action(
        "cli-sess", 1, ActionCategory.RECON, "curl", "get", "Inspect HTTP endpoint",
        target_id="enemy-03", workflow_id=wf.workflow_id, mission_id=m.mission_id,
        evidence_id=ev.id,
    )
    ops.record_sla(1, "enemy-03", "tcp/8080", SlaStatus.OK, latency_ms=15.0, workflow_id=wf.workflow_id, mission_id=m.mission_id)

    return db_path, sink_path, m.mission_id, ev.id


def test_cli_awareness_mission_text_and_json(capsys):
    with tempfile.TemporaryDirectory() as d:
        db_path, sink_path, mid, _ = _setup_cli_env(d)

        # 1. Text output
        rc = main(["--state-db", db_path, "--sink", sink_path, "awareness", "--mission", mid])
        assert rc == 0
        out_text = capsys.readouterr().out
        assert f"SITUATIONAL AWARENESS: MISSION #{mid[:8]}" in out_text
        assert "CLI Mission" in out_text
        assert "enemy-03" in out_text
        assert "TCP/8080" in out_text
        assert "HEALTHY" in out_text
        assert "evidence artifact(s) correlated" in out_text

        # 2. JSON output
        rc = main(["--state-db", db_path, "--sink", sink_path, "awareness", "--mission", mid, "--json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["mission_id"] == mid
        assert data["target"]["host"] == "10.0.0.3"
        assert data["health"]["health_trajectory"] == "healthy"
        assert len(data["evidence"]) >= 1


def test_cli_awareness_target_text_and_json(capsys):
    with tempfile.TemporaryDirectory() as d:
        db_path, sink_path, _, _ = _setup_cli_env(d)

        # 1. Text output
        rc = main(["--state-db", db_path, "--sink", sink_path, "awareness", "--target", "enemy-03"])
        assert rc == 0
        out_text = capsys.readouterr().out
        assert "SITUATIONAL AWARENESS: TARGET enemy-03" in out_text
        assert "10.0.0.3" in out_text
        assert "8080/tcp" in out_text

        # 2. JSON output
        rc = main(["--state-db", db_path, "--sink", sink_path, "awareness", "--target", "enemy-03", "--json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["target_id"] == "enemy-03"
        assert len(data["missions"]) >= 1


def test_cli_awareness_evidence_inspection(capsys):
    with tempfile.TemporaryDirectory() as d:
        db_path, sink_path, _, ev_id = _setup_cli_env(d)

        # 1. Text output
        rc = main(["--state-db", db_path, "--sink", sink_path, "awareness", "--evidence", ev_id])
        assert rc == 0
        out_text = capsys.readouterr().out
        assert f"EVIDENCE INSPECTION: {ev_id}" in out_text
        assert "tool_http" in out_text
        assert "200" in out_text

        # 2. JSON output
        rc = main(["--state-db", db_path, "--sink", sink_path, "awareness", "--evidence", ev_id, "--json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["id"] == ev_id
        assert data["payload"]["status_code"] == 200


def test_cli_awareness_errors(capsys):
    with tempfile.TemporaryDirectory() as d:
        db_path, sink_path, _, _ = _setup_cli_env(d)

        # Missing required flags
        with pytest.raises(SystemExit, match="awareness requires"):
            main(["--state-db", db_path, "--sink", sink_path, "awareness"])

        # Non-existent mission
        with pytest.raises(SystemExit, match="Mission not found"):
            main(["--state-db", db_path, "--sink", sink_path, "awareness", "--mission", "bad-mid"])

        # Non-existent evidence
        with pytest.raises(SystemExit, match="Evidence not found"):
            main(["--state-db", db_path, "--sink", sink_path, "awareness", "--evidence", "bad-evid"])
