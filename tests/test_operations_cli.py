import json
import tempfile
from io import StringIO
import sys

from attnndef.cli import main
from attnndef.context import ContextStore, OperatorContext
from attnndef.targets import Role, Target, TargetService


def run_cli(*args):
    buf_out = StringIO()
    buf_err = StringIO()
    old_out = sys.stdout
    old_err = sys.stderr
    try:
        sys.stdout = buf_out
        sys.stderr = buf_err
        ret = main(list(args))
    finally:
        sys.stdout = old_out
        sys.stderr = old_err
    return ret, buf_out.getvalue(), buf_err.getvalue()


def test_cli_operations_round_and_ticks():
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        # 1. Start round 1
        ret, out, _ = run_cli("--state-db", db_path, "round", "--set", "1")
        assert ret == 0
        assert "Round #1 started" in out

        # 2. Record tick 1
        ret, out, _ = run_cli("--state-db", db_path, "round", "--tick", "1")
        assert ret == 0
        assert "Tick #1 recorded for round #1" in out

        # 3. List rounds with --json
        ret, out, _ = run_cli("--state-db", db_path, "round", "--list", "--json")
        assert ret == 0
        data = json.loads(out)
        assert len(data) >= 1
        assert data[0]["round_number"] == 1


def test_cli_operations_action_and_timeline():
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        tgt_svc = TargetService(db_path)
        tgt_svc.add_target(Target("box-1", "box-1", "10.0.0.5", Role.ENEMY))

        # 1. Start round
        run_cli("--state-db", db_path, "round", "--set", "1")

        # 2. Record action
        ret, out, _ = run_cli(
            "--state-db", db_path, "action", "--record",
            "--category", "recon", "--target", "box-1",
            "--tool", "nmap", "--op", "scan", "--summary", "Quick port scan"
        )
        assert ret == 0
        assert "Action [RECON] recorded" in out

        # 3. Record attack
        ret, out, _ = run_cli(
            "--state-db", db_path, "attack", "--record",
            "--target", "box-1", "--service", "http/80",
            "--method", "directory traversal", "--status", "success"
        )
        assert ret == 0
        assert "Attack [" in out

        # 4. Record flag (fingerprint only, no plaintext stored)
        ret, out, _ = run_cli(
            "--state-db", db_path, "flag", "--record", "flag{cli_captured_flag_12345}",
            "--target", "box-1", "--source", "curl", "--status", "validated"
        )
        assert ret == 0
        assert "Flag [" in out
        assert "flag{...12345}" in out

        # 5. Record SLA observation
        ret, out, _ = run_cli(
            "--state-db", db_path, "sla", "--record",
            "--target", "box-1", "--service", "http/80",
            "--status", "ok", "--latency", "45.0"
        )
        assert ret == 0
        assert "SLA recorded" in out

        # 6. View Timeline
        ret, out, _ = run_cli("--state-db", db_path, "timeline", "--json")
        assert ret == 0
        timeline = json.loads(out)
        assert len(timeline) == 4
        categories = {e["category"] for e in timeline}
        assert {"RECON", "ATTACK", "FLAG", "SLA"}.issubset(categories)
