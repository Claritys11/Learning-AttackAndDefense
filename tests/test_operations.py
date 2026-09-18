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
    make_flag_fingerprint,
)


def test_session_lifecycle_and_persistence():
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        svc = OperationService(db_path)

        session = svc.create_session(
            competition="Grand Final Attack & Defense",
            platform="jjz.jatimprov.go.id",
            team_id="team-04",
            operator="Kai",
            vpn_interface="wg0",
            own_ip="10.10.4.2",
            enemy_subnet="10.10.0.0/16",
        )
        assert session.status == SessionStatus.ACTIVE
        assert session.session_id

        # Query active session
        active = svc.get_active_session()
        assert active is not None
        assert active.session_id == session.session_id
        assert active.operator == "Kai"

        # End session
        assert svc.end_session(session.session_id) is True
        ended = svc.get_session(session.session_id)
        assert ended.status == SessionStatus.ENDED
        assert ended.ended_at is not None

        # Re-open with new service instance to verify persistence
        svc2 = OperationService(db_path)
        persisted = svc2.get_session(session.session_id)
        assert persisted is not None
        assert persisted.team_id == "team-04"
        assert persisted.status == SessionStatus.ENDED


def test_round_and_tick_tracking():
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        svc = OperationService(db_path)
        session = svc.create_session(team_id="team-04", operator="Kai")

        # Start Round 1
        r1 = svc.start_round(session.session_id, 1)
        assert r1.round_id == 1
        assert r1.status == RoundStatus.ACTIVE

        # Record local ticks
        t1 = svc.record_tick(session.session_id, 1, 1)
        t2 = svc.record_tick(session.session_id, 1, 2)
        ticks = svc.list_ticks(1)
        assert len(ticks) == 2
        assert ticks[0].tick_number == 1
        assert ticks[1].tick_number == 2

        # Advance to Round 2 (should complete round 1)
        r2 = svc.start_round(session.session_id, 2)
        assert r2.round_id == 2
        assert svc.get_round(1).status == RoundStatus.ENDED
        assert svc.get_round(2).status == RoundStatus.ACTIVE

        # Complete Round 2
        assert svc.complete_round(2) is True
        assert svc.get_round(2).status == RoundStatus.ENDED


def test_operator_action_recording_and_filtering():
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        svc = OperationService(db_path)
        session = svc.create_session(team_id="team-04", operator="Kai")

        a1 = svc.record_action(
            session.session_id,
            1,
            ActionCategory.RECON,
            "nmap",
            "port_scan",
            "Nmap scan of enemy-web-01",
            target_id="enemy-web-01",
            details={"ports": "80,443"},
        )
        a2 = svc.record_action(
            session.session_id,
            1,
            ActionCategory.ATTACK,
            "http",
            "post_request",
            "Exploit payload sent to /api/vuln",
            target_id="enemy-web-01",
        )
        a3 = svc.record_action(
            session.session_id,
            1,
            ActionCategory.DEFENSE,
            "system",
            "service_restart",
            "Restarted nginx on own-box",
            target_id="own-box",
        )

        # Filtering
        all_actions = svc.list_actions(round_id=1)
        assert len(all_actions) == 3

        enemy_actions = svc.list_actions(target_id="enemy-web-01")
        assert len(enemy_actions) == 2

        recon_actions = svc.list_actions(category=ActionCategory.RECON)
        assert len(recon_actions) == 1
        assert recon_actions[0].details == {"ports": "80,443"}


def test_attack_and_defense_record_lifecycle():
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        svc = OperationService(db_path)

        # Attack lifecycle
        atk = svc.record_attack(
            1, "enemy-box", "http/80", "SQL injection on login form", notes="Testing admin bypass"
        )
        assert atk.status == AttackStatus.PLANNED

        assert svc.update_attack_status(atk.id, AttackStatus.SUCCESS, notes="Retrieved DB flag") is True
        updated_atk = svc.list_attacks(round_id=1)[0]
        assert updated_atk.status == AttackStatus.SUCCESS
        assert "Retrieved DB flag" in updated_atk.notes
        assert updated_atk.completed_at is not None

        # Defense lifecycle
        defn = svc.record_defense(
            1, "own-box", "nginx/80", "Added WAF rule to block UNION SELECT", notes="Mitigating SQLi"
        )
        assert defn.status == DefenseStatus.PLANNED

        assert svc.update_defense_status(defn.id, DefenseStatus.COMPLETED, notes="Reloaded nginx") is True
        updated_defn = svc.list_defenses(round_id=1)[0]
        assert updated_defn.status == DefenseStatus.COMPLETED


def test_flag_record_and_no_plaintext_persistence():
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        svc = OperationService(db_path)

        raw_secret_flag = "flag{th1s_is_a_very_s3cr3t_dynamic_flag_12345}"
        flag_rec = svc.record_flag(
            round_id=1,
            target_id="enemy-box",
            source="HTTP response",
            raw_flag_or_fingerprint=raw_secret_flag,
            status=FlagStatus.VALIDATED,
            notes="Recovered from /api/debug",
        )

        assert flag_rec.status == FlagStatus.VALIDATED
        assert flag_rec.fingerprint.startswith("sha256:")
        # Plaintext must not be in fingerprint or preview
        assert raw_secret_flag not in flag_rec.fingerprint
        assert flag_rec.flag_preview == "flag{...12345}"

        # Direct database verification: raw secret flag must NEVER appear in raw database text
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        rows = cur.execute("SELECT * FROM flag_records").fetchall()
        db_dump = str(rows)
        conn.close()

        assert raw_secret_flag not in db_dump
        assert "s3cr3t_dynamic" not in db_dump

        # Update status
        assert svc.update_flag_status(flag_rec.id, FlagStatus.SUBMITTED, notes="Submitted externally") is True
        updated = svc.list_flags(round_id=1)[0]
        assert updated.status == FlagStatus.SUBMITTED


def test_sla_observation_recording():
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        svc = OperationService(db_path)

        obs = svc.record_sla(
            round_id=1,
            target_id="own-web",
            service="http/80",
            status=SlaStatus.OK,
            latency_ms=42.5,
            source="local",
            details={"http_status": 200},
        )
        assert obs.status == SlaStatus.OK
        assert obs.latency_ms == 42.5
        assert obs.source == "local"

        all_sla = svc.list_sla(target_id="own-web")
        assert len(all_sla) == 1
        assert all_sla[0].details == {"http_status": 200}


def test_timeline_deterministic_ordering():
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        svc = OperationService(db_path)
        session = svc.create_session(team_id="team-04", operator="Kai")

        # Create multiple items with staggered timestamps
        svc.record_action(
            session.session_id, 1, ActionCategory.RECON, "nmap", "scan", "Port scan", target_id="box-1", timestamp=100.0
        )
        svc.record_attack(1, "box-1", "http", "GET /exploit", started_at=105.0)
        svc.record_flag(1, "box-1", "http", "flag{1234567890}", observed_at=110.0)
        svc.record_defense(1, "box-own", "nginx", "Patch config", started_at=115.0)
        svc.record_sla(1, "box-own", "http", SlaStatus.OK, latency_ms=12.0, observed_at=120.0)

        timeline = svc.get_timeline(round_id=1)
        assert len(timeline) == 5

        # Must be sorted descending by timestamp
        timestamps = [e.timestamp for e in timeline]
        assert timestamps == sorted(timestamps, reverse=True)
        assert timeline[0].category == "SLA"
        assert timeline[1].category == "DEFENSE"
        assert timeline[2].category == "FLAG"
        assert timeline[3].category == "ATTACK"
        assert timeline[4].category == "RECON"


def test_target_validation_with_registry():
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        tgt_svc = TargetService(db_path)
        tgt_svc.add_target(Target("valid-box", "valid-box", "10.0.0.5", Role.ENEMY))

        svc = OperationService(db_path, target_service=tgt_svc)

        # Valid target succeeds
        atk = svc.record_attack(1, "valid-box", "ssh", "key audit")
        assert atk.target_id == "valid-box"

        # Invalid target raises ValueError
        with pytest.raises(ValueError, match="target not found in registry: non-existent"):
            svc.record_attack(1, "non-existent", "ssh", "fail")

        with pytest.raises(ValueError, match="target not found in registry: bad-box"):
            svc.record_defense(1, "bad-box", "nginx", "fail")

        with pytest.raises(ValueError, match="target not found in registry: bad-box"):
            svc.record_flag(1, "bad-box", "http", "flag{test12345}")

        with pytest.raises(ValueError, match="target not found in registry: bad-box"):
            svc.record_sla(1, "bad-box", "http", SlaStatus.OK)
