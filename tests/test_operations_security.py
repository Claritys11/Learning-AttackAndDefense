import os
import re
import sqlite3
import tempfile
import pytest

from attnndef.operations import (
    AttackStatus,
    FlagStatus,
    OperationService,
    SlaStatus,
)
from attnndef.targets import Role, Target, TargetService


def test_security_no_shell_or_insecure_apis():
    # Scan src/ for forbidden execution primitives
    src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../src"))
    forbidden_patterns = [
        r"shell\s*=\s*True",
        r"os\.system\(",
        r"os\.popen\(",
    ]
    for root, _, files in os.walk(src_dir):
        for f in files:
            if not f.endswith(".py"):
                continue
            path = os.path.join(root, f)
            content = open(path, "r", encoding="utf-8").read()
            for pat in forbidden_patterns:
                assert not re.search(pat, content), f"Forbidden pattern '{pat}' found in {path}"


def test_security_no_remote_competition_calls():
    # Operations service and models must not make remote HTTP/socket calls or automate submissions
    src_ops = os.path.abspath(os.path.join(os.path.dirname(__file__), "../src/attnndef/operations"))
    forbidden_remote = [
        r"requests\.",
        r"urllib\.request",
        r"aiohttp",
        r"httpx",
    ]
    for root, _, files in os.walk(src_ops):
        for f in files:
            if not f.endswith(".py"):
                continue
            path = os.path.join(root, f)
            content = open(path, "r", encoding="utf-8").read()
            for pat in forbidden_remote:
                assert not re.search(pat, content), f"Unexpected network library '{pat}' found in {path}"


def test_security_no_plaintext_flag_in_database():
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        svc = OperationService(db_path)

        secret = "flag{super_confidential_raw_flag_value_xyz789}"
        svc.record_flag(1, "target-1", "HTTP response", secret, status=FlagStatus.OBSERVED)

        # Inspect entire SQLite database file contents
        raw_db_bytes = open(db_path, "rb").read()
        assert b"super_confidential_raw_flag" not in raw_db_bytes
        assert b"xyz789}" not in raw_db_bytes


def test_security_foreign_key_enforcement():
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        svc = OperationService(db_path)

        # Inserting a round with an empty/non-existent session when FKs are on:
        # start_round auto-upserts session if needed, but manual round insert without valid session must fail
        with svc._db() as db:
            with pytest.raises(sqlite3.IntegrityError):
                db.execute(
                    "INSERT INTO operational_rounds(round_id, session_id, round_number, started_at, status) "
                    "VALUES (999, 'uncreated-session-id', 999, 100.0, 'active')"
                )


def test_security_invalid_target_rejection():
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        tgt_svc = TargetService(db_path)
        tgt_svc.add_target(Target("allowed-target", "allowed-target", "10.0.0.1", Role.ENEMY))

        svc = OperationService(db_path, target_service=tgt_svc)

        # Attack with non-existent target rejected
        with pytest.raises(ValueError, match="target not found in registry: fake-target"):
            svc.record_attack(1, "fake-target", "http", "GET /test")

        # Defense with non-existent target rejected
        with pytest.raises(ValueError, match="target not found in registry: fake-target"):
            svc.record_defense(1, "fake-target", "nginx", "restart")

        # Flag with non-existent target rejected
        with pytest.raises(ValueError, match="target not found in registry: fake-target"):
            svc.record_flag(1, "fake-target", "http", "flag{12345}")

        # SLA with non-existent target rejected
        with pytest.raises(ValueError, match="target not found in registry: fake-target"):
            svc.record_sla(1, "fake-target", "http", SlaStatus.OK)
