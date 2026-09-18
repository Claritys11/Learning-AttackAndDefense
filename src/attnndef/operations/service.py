from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import time
import uuid

from .models import (
    ActionCategory,
    AttackRecord,
    AttackStatus,
    DefenseRecord,
    DefenseStatus,
    FlagRecord,
    FlagStatus,
    OperatorAction,
    Round,
    RoundStatus,
    Session,
    SessionStatus,
    SlaObservation,
    SlaStatus,
    TimelineEntry,
    Tick,
    make_flag_fingerprint,
)


class OperationService:
    """SQLite-backed Attack & Defense operational state and action tracking service."""

    def __init__(self, db_path: str | Path, target_service=None):
        self.path = Path(db_path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.target_service = target_service
        self._init()

    def _db(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        return db

    def _init(self):
        with self._db() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS operational_sessions (
                session_id TEXT PRIMARY KEY,
                competition TEXT NOT NULL,
                platform TEXT NOT NULL,
                team_id TEXT NOT NULL,
                operator TEXT NOT NULL,
                vpn_interface TEXT NOT NULL,
                own_ip TEXT NOT NULL,
                enemy_subnet TEXT NOT NULL,
                started_at REAL NOT NULL,
                ended_at REAL,
                status TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS operational_rounds (
                round_id INTEGER PRIMARY KEY,
                session_id TEXT NOT NULL,
                round_number INTEGER NOT NULL,
                started_at REAL NOT NULL,
                ended_at REAL,
                status TEXT NOT NULL,
                FOREIGN KEY(session_id) REFERENCES operational_sessions(session_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS operational_ticks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                round_id INTEGER NOT NULL,
                tick_number INTEGER NOT NULL,
                observed_at REAL NOT NULL,
                status TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS operator_actions (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                round_id INTEGER NOT NULL,
                timestamp REAL NOT NULL,
                category TEXT NOT NULL,
                target_id TEXT,
                tool TEXT NOT NULL,
                operation TEXT NOT NULL,
                summary TEXT NOT NULL,
                status TEXT NOT NULL,
                evidence_id TEXT,
                details TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS attack_records (
                id TEXT PRIMARY KEY,
                round_id INTEGER NOT NULL,
                target_id TEXT NOT NULL,
                service TEXT NOT NULL,
                method TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at REAL NOT NULL,
                completed_at REAL,
                notes TEXT NOT NULL,
                evidence_id TEXT
            );

            CREATE TABLE IF NOT EXISTS defense_records (
                id TEXT PRIMARY KEY,
                round_id INTEGER NOT NULL,
                target_id TEXT NOT NULL,
                service TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at REAL NOT NULL,
                completed_at REAL,
                notes TEXT NOT NULL,
                evidence_id TEXT
            );

            CREATE TABLE IF NOT EXISTS flag_records (
                id TEXT PRIMARY KEY,
                round_id INTEGER NOT NULL,
                target_id TEXT NOT NULL,
                source TEXT NOT NULL,
                observed_at REAL NOT NULL,
                status TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                flag_preview TEXT NOT NULL,
                notes TEXT NOT NULL,
                evidence_id TEXT
            );

            CREATE TABLE IF NOT EXISTS sla_observations (
                id TEXT PRIMARY KEY,
                round_id INTEGER NOT NULL,
                target_id TEXT NOT NULL,
                service TEXT NOT NULL,
                observed_at REAL NOT NULL,
                status TEXT NOT NULL,
                latency_ms REAL,
                source TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '{}'
            );

            CREATE INDEX IF NOT EXISTS idx_operator_actions_round ON operator_actions(round_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_operator_actions_target ON operator_actions(target_id);
            CREATE INDEX IF NOT EXISTS idx_attack_records_round ON attack_records(round_id);
            CREATE INDEX IF NOT EXISTS idx_defense_records_round ON defense_records(round_id);
            CREATE INDEX IF NOT EXISTS idx_flag_records_round ON flag_records(round_id);
            CREATE INDEX IF NOT EXISTS idx_sla_obs_target ON sla_observations(target_id, observed_at);
            """)

    def _validate_target(self, target_id: str | None):
        if not target_id:
            return
        if self.target_service is not None:
            tgt = self.target_service.get_target(target_id)
            if tgt is None:
                raise ValueError(f"target not found in registry: {target_id}")

    # --- SESSIONS ---

    def create_session(
        self,
        competition: str = "Grand Final Attack & Defense",
        platform: str = "jjz.jatimprov.go.id",
        team_id: str = "",
        operator: str = "",
        vpn_interface: str = "wg0",
        own_ip: str = "",
        enemy_subnet: str = "",
        session_id: str | None = None,
    ) -> Session:
        sid = session_id or str(uuid.uuid4())
        started = time.time()
        with self._db() as db:
            db.execute(
                """INSERT INTO operational_sessions(
                    session_id, competition, platform, team_id, operator,
                    vpn_interface, own_ip, enemy_subnet, started_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    sid,
                    competition,
                    platform,
                    team_id,
                    operator,
                    vpn_interface,
                    own_ip,
                    enemy_subnet,
                    started,
                    SessionStatus.ACTIVE.value,
                ),
            )
        return Session(
            session_id=sid,
            competition=competition,
            platform=platform,
            team_id=team_id,
            operator=operator,
            vpn_interface=vpn_interface,
            own_ip=own_ip,
            enemy_subnet=enemy_subnet,
            started_at=started,
            status=SessionStatus.ACTIVE,
        )

    def get_session(self, session_id: str) -> Session | None:
        with self._db() as db:
            row = db.execute("SELECT * FROM operational_sessions WHERE session_id = ?", (session_id,)).fetchone()
        if not row:
            return None
        return Session(
            session_id=row["session_id"],
            competition=row["competition"],
            platform=row["platform"],
            team_id=row["team_id"],
            operator=row["operator"],
            vpn_interface=row["vpn_interface"],
            own_ip=row["own_ip"],
            enemy_subnet=row["enemy_subnet"],
            started_at=row["started_at"],
            ended_at=row["ended_at"],
            status=SessionStatus(row["status"]),
        )

    def get_active_session(self) -> Session | None:
        with self._db() as db:
            row = db.execute(
                "SELECT * FROM operational_sessions WHERE status = ? ORDER BY started_at DESC LIMIT 1",
                (SessionStatus.ACTIVE.value,),
            ).fetchone()
        if not row:
            return None
        return Session(
            session_id=row["session_id"],
            competition=row["competition"],
            platform=row["platform"],
            team_id=row["team_id"],
            operator=row["operator"],
            vpn_interface=row["vpn_interface"],
            own_ip=row["own_ip"],
            enemy_subnet=row["enemy_subnet"],
            started_at=row["started_at"],
            ended_at=row["ended_at"],
            status=SessionStatus(row["status"]),
        )

    def end_session(self, session_id: str) -> bool:
        now = time.time()
        with self._db() as db:
            cur = db.execute(
                "UPDATE operational_sessions SET status = ?, ended_at = ? WHERE session_id = ?",
                (SessionStatus.ENDED.value, now, session_id),
            )
        return cur.rowcount > 0

    # --- ROUNDS ---

    def start_round(self, session_id: str, round_number: int) -> Round:
        # Mark any previous active rounds for this session as ended
        now = time.time()
        with self._db() as db:
            row = db.execute("SELECT session_id FROM operational_sessions WHERE session_id = ?", (session_id,)).fetchone()
            if not row:
                db.execute(
                    """INSERT INTO operational_sessions(
                        session_id, competition, platform, team_id, operator,
                        vpn_interface, own_ip, enemy_subnet, started_at, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        session_id,
                        "Grand Final Attack & Defense",
                        "jjz.jatimprov.go.id",
                        "",
                        "",
                        "wg0",
                        "",
                        "",
                        now,
                        SessionStatus.ACTIVE.value,
                    ),
                )
            db.execute(
                "UPDATE operational_rounds SET status = ?, ended_at = ? WHERE session_id = ? AND status = ?",
                (RoundStatus.ENDED.value, now, session_id, RoundStatus.ACTIVE.value),
            )
            db.execute(
                """INSERT INTO operational_rounds(
                    round_id, session_id, round_number, started_at, status
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(round_id) DO UPDATE SET
                    status = excluded.status,
                    started_at = excluded.started_at,
                    ended_at = NULL""",
                (round_number, session_id, round_number, now, RoundStatus.ACTIVE.value),
            )
        return Round(
            round_id=round_number,
            session_id=session_id,
            round_number=round_number,
            started_at=now,
            status=RoundStatus.ACTIVE,
        )

    def get_round(self, round_id: int) -> Round | None:
        with self._db() as db:
            row = db.execute("SELECT * FROM operational_rounds WHERE round_id = ?", (round_id,)).fetchone()
        if not row:
            return None
        return Round(
            round_id=row["round_id"],
            session_id=row["session_id"],
            round_number=row["round_number"],
            started_at=row["started_at"],
            ended_at=row["ended_at"],
            status=RoundStatus(row["status"]),
        )

    def get_active_round(self, session_id: str) -> Round | None:
        with self._db() as db:
            row = db.execute(
                "SELECT * FROM operational_rounds WHERE session_id = ? AND status = ? ORDER BY round_number DESC LIMIT 1",
                (session_id, RoundStatus.ACTIVE.value),
            ).fetchone()
        if not row:
            return None
        return Round(
            round_id=row["round_id"],
            session_id=row["session_id"],
            round_number=row["round_number"],
            started_at=row["started_at"],
            ended_at=row["ended_at"],
            status=RoundStatus(row["status"]),
        )

    def complete_round(self, round_id: int) -> bool:
        now = time.time()
        with self._db() as db:
            cur = db.execute(
                "UPDATE operational_rounds SET status = ?, ended_at = ? WHERE round_id = ?",
                (RoundStatus.ENDED.value, now, round_id),
            )
        return cur.rowcount > 0

    def list_rounds(self, session_id: str) -> list[Round]:
        with self._db() as db:
            rows = db.execute(
                "SELECT * FROM operational_rounds WHERE session_id = ? ORDER BY round_number ASC",
                (session_id,),
            ).fetchall()
        return [
            Round(
                round_id=r["round_id"],
                session_id=r["session_id"],
                round_number=r["round_number"],
                started_at=r["started_at"],
                ended_at=r["ended_at"],
                status=RoundStatus(r["status"]),
            )
            for r in rows
        ]

    # --- TICKS ---

    def record_tick(
        self, session_id: str, round_id: int, tick_number: int, status: str = "observed"
    ) -> Tick:
        now = time.time()
        with self._db() as db:
            cur = db.execute(
                """INSERT INTO operational_ticks(session_id, round_id, tick_number, observed_at, status)
                VALUES (?, ?, ?, ?, ?)""",
                (session_id, round_id, tick_number, now, status),
            )
        return Tick(
            id=cur.lastrowid,
            session_id=session_id,
            round_id=round_id,
            tick_number=tick_number,
            observed_at=now,
            status=status,
        )

    def list_ticks(self, round_id: int) -> list[Tick]:
        with self._db() as db:
            rows = db.execute(
                "SELECT * FROM operational_ticks WHERE round_id = ? ORDER BY tick_number ASC",
                (round_id,),
            ).fetchall()
        return [
            Tick(
                id=r["id"],
                session_id=r["session_id"],
                round_id=r["round_id"],
                tick_number=r["tick_number"],
                observed_at=r["observed_at"],
                status=r["status"],
            )
            for r in rows
        ]

    # --- OPERATOR ACTIONS ---

    def record_action(
        self,
        session_id: str,
        round_id: int,
        category: ActionCategory,
        tool: str,
        operation: str,
        summary: str,
        *,
        target_id: str | None = None,
        status: str = "completed",
        evidence_id: str | None = None,
        details: dict | None = None,
        timestamp: float | None = None,
    ) -> OperatorAction:
        self._validate_target(target_id)
        action_id = str(uuid.uuid4())
        ts = timestamp or time.time()
        details_json = json.dumps(details or {}, sort_keys=True)
        with self._db() as db:
            db.execute(
                """INSERT INTO operator_actions(
                    id, session_id, round_id, timestamp, category, target_id,
                    tool, operation, summary, status, evidence_id, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    action_id,
                    session_id,
                    round_id,
                    ts,
                    category.value,
                    target_id,
                    tool,
                    operation,
                    summary,
                    status,
                    evidence_id,
                    details_json,
                ),
            )
        return OperatorAction(
            id=action_id,
            session_id=session_id,
            round_id=round_id,
            timestamp=ts,
            category=category,
            target_id=target_id,
            tool=tool,
            operation=operation,
            summary=summary,
            status=status,
            evidence_id=evidence_id,
            details=details or {},
        )

    def list_actions(
        self,
        round_id: int | None = None,
        target_id: str | None = None,
        category: ActionCategory | None = None,
        limit: int = 100,
    ) -> list[OperatorAction]:
        query = "SELECT * FROM operator_actions WHERE 1=1"
        params: list = []
        if round_id is not None:
            query += " AND round_id = ?"
            params.append(round_id)
        if target_id is not None:
            query += " AND target_id = ?"
            params.append(target_id)
        if category is not None:
            query += " AND category = ?"
            params.append(category.value)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._db() as db:
            rows = db.execute(query, params).fetchall()
        return [
            OperatorAction(
                id=r["id"],
                session_id=r["session_id"],
                round_id=r["round_id"],
                timestamp=r["timestamp"],
                category=ActionCategory(r["category"]),
                target_id=r["target_id"],
                tool=r["tool"],
                operation=r["operation"],
                summary=r["summary"],
                status=r["status"],
                evidence_id=r["evidence_id"],
                details=json.loads(r["details"]),
            )
            for r in rows
        ]

    # --- ATTACKS ---

    def record_attack(
        self,
        round_id: int,
        target_id: str,
        service: str,
        method: str,
        *,
        status: AttackStatus = AttackStatus.PLANNED,
        notes: str = "",
        evidence_id: str | None = None,
        started_at: float | None = None,
    ) -> AttackRecord:
        self._validate_target(target_id)
        attack_id = str(uuid.uuid4())
        started = started_at or time.time()
        with self._db() as db:
            db.execute(
                """INSERT INTO attack_records(
                    id, round_id, target_id, service, method, status, started_at, notes, evidence_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (attack_id, round_id, target_id, service, method, status.value, started, notes, evidence_id),
            )
        return AttackRecord(
            id=attack_id,
            round_id=round_id,
            target_id=target_id,
            service=service,
            method=method,
            status=status,
            started_at=started,
            notes=notes,
            evidence_id=evidence_id,
        )

    def update_attack_status(
        self,
        attack_id: str,
        status: AttackStatus,
        *,
        notes: str | None = None,
        completed_at: float | None = None,
    ) -> bool:
        now = completed_at if completed_at is not None else time.time()
        with self._db() as db:
            if notes is not None:
                cur = db.execute(
                    "UPDATE attack_records SET status = ?, completed_at = ?, notes = ? WHERE id = ?",
                    (status.value, now, notes, attack_id),
                )
            else:
                cur = db.execute(
                    "UPDATE attack_records SET status = ?, completed_at = ? WHERE id = ?",
                    (status.value, now, attack_id),
                )
        return cur.rowcount > 0

    def list_attacks(
        self, round_id: int | None = None, target_id: str | None = None, limit: int = 100
    ) -> list[AttackRecord]:
        query = "SELECT * FROM attack_records WHERE 1=1"
        params: list = []
        if round_id is not None:
            query += " AND round_id = ?"
            params.append(round_id)
        if target_id is not None:
            query += " AND target_id = ?"
            params.append(target_id)
        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)

        with self._db() as db:
            rows = db.execute(query, params).fetchall()
        return [
            AttackRecord(
                id=r["id"],
                round_id=r["round_id"],
                target_id=r["target_id"],
                service=r["service"],
                method=r["method"],
                status=AttackStatus(r["status"]),
                started_at=r["started_at"],
                completed_at=r["completed_at"],
                notes=r["notes"],
                evidence_id=r["evidence_id"],
            )
            for r in rows
        ]

    # --- DEFENSES ---

    def record_defense(
        self,
        round_id: int,
        target_id: str,
        service: str,
        action: str,
        *,
        status: DefenseStatus = DefenseStatus.PLANNED,
        notes: str = "",
        evidence_id: str | None = None,
        started_at: float | None = None,
    ) -> DefenseRecord:
        self._validate_target(target_id)
        defense_id = str(uuid.uuid4())
        started = started_at or time.time()
        with self._db() as db:
            db.execute(
                """INSERT INTO defense_records(
                    id, round_id, target_id, service, action, status, started_at, notes, evidence_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (defense_id, round_id, target_id, service, action, status.value, started, notes, evidence_id),
            )
        return DefenseRecord(
            id=defense_id,
            round_id=round_id,
            target_id=target_id,
            service=service,
            action=action,
            status=status,
            started_at=started,
            notes=notes,
            evidence_id=evidence_id,
        )

    def update_defense_status(
        self,
        defense_id: str,
        status: DefenseStatus,
        *,
        notes: str | None = None,
        completed_at: float | None = None,
    ) -> bool:
        now = completed_at if completed_at is not None else time.time()
        with self._db() as db:
            if notes is not None:
                cur = db.execute(
                    "UPDATE defense_records SET status = ?, completed_at = ?, notes = ? WHERE id = ?",
                    (status.value, now, notes, defense_id),
                )
            else:
                cur = db.execute(
                    "UPDATE defense_records SET status = ?, completed_at = ? WHERE id = ?",
                    (status.value, now, defense_id),
                )
        return cur.rowcount > 0

    def list_defenses(
        self, round_id: int | None = None, target_id: str | None = None, limit: int = 100
    ) -> list[DefenseRecord]:
        query = "SELECT * FROM defense_records WHERE 1=1"
        params: list = []
        if round_id is not None:
            query += " AND round_id = ?"
            params.append(round_id)
        if target_id is not None:
            query += " AND target_id = ?"
            params.append(target_id)
        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)

        with self._db() as db:
            rows = db.execute(query, params).fetchall()
        return [
            DefenseRecord(
                id=r["id"],
                round_id=r["round_id"],
                target_id=r["target_id"],
                service=r["service"],
                action=r["action"],
                status=DefenseStatus(r["status"]),
                started_at=r["started_at"],
                completed_at=r["completed_at"],
                notes=r["notes"],
                evidence_id=r["evidence_id"],
            )
            for r in rows
        ]

    # --- FLAGS ---

    def record_flag(
        self,
        round_id: int,
        target_id: str,
        source: str,
        raw_flag_or_fingerprint: str,
        *,
        status: FlagStatus = FlagStatus.OBSERVED,
        notes: str = "",
        evidence_id: str | None = None,
        observed_at: float | None = None,
    ) -> FlagRecord:
        self._validate_target(target_id)
        flag_id = str(uuid.uuid4())
        ts = observed_at or time.time()

        # Generate fingerprint and masked preview; NEVER store raw plaintext flag
        cleaned = raw_flag_or_fingerprint.strip()
        if cleaned.startswith("sha256:"):
            fingerprint = cleaned
            flag_preview = "<hash>"
        else:
            fp, preview = make_flag_fingerprint(cleaned)
            fingerprint = f"sha256:{fp}"
            flag_preview = preview

        with self._db() as db:
            db.execute(
                """INSERT INTO flag_records(
                    id, round_id, target_id, source, observed_at, status,
                    fingerprint, flag_preview, notes, evidence_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    flag_id,
                    round_id,
                    target_id,
                    source,
                    ts,
                    status.value,
                    fingerprint,
                    flag_preview,
                    notes,
                    evidence_id,
                ),
            )
        return FlagRecord(
            id=flag_id,
            round_id=round_id,
            target_id=target_id,
            source=source,
            observed_at=ts,
            status=status,
            fingerprint=fingerprint,
            flag_preview=flag_preview,
            notes=notes,
            evidence_id=evidence_id,
        )

    def update_flag_status(
        self, flag_id: str, status: FlagStatus, *, notes: str | None = None
    ) -> bool:
        with self._db() as db:
            if notes is not None:
                cur = db.execute(
                    "UPDATE flag_records SET status = ?, notes = ? WHERE id = ?",
                    (status.value, notes, flag_id),
                )
            else:
                cur = db.execute(
                    "UPDATE flag_records SET status = ? WHERE id = ?",
                    (status.value, flag_id),
                )
        return cur.rowcount > 0

    def list_flags(
        self, round_id: int | None = None, target_id: str | None = None, limit: int = 100
    ) -> list[FlagRecord]:
        query = "SELECT * FROM flag_records WHERE 1=1"
        params: list = []
        if round_id is not None:
            query += " AND round_id = ?"
            params.append(round_id)
        if target_id is not None:
            query += " AND target_id = ?"
            params.append(target_id)
        query += " ORDER BY observed_at DESC LIMIT ?"
        params.append(limit)

        with self._db() as db:
            rows = db.execute(query, params).fetchall()
        return [
            FlagRecord(
                id=r["id"],
                round_id=r["round_id"],
                target_id=r["target_id"],
                source=r["source"],
                observed_at=r["observed_at"],
                status=FlagStatus(r["status"]),
                fingerprint=r["fingerprint"],
                flag_preview=r["flag_preview"],
                notes=r["notes"],
                evidence_id=r["evidence_id"],
            )
            for r in rows
        ]

    # --- SLA / HEALTH OBSERVATIONS ---

    def record_sla(
        self,
        round_id: int,
        target_id: str,
        service: str,
        status: SlaStatus,
        *,
        latency_ms: float | None = None,
        source: str = "local",
        details: dict | None = None,
        observed_at: float | None = None,
    ) -> SlaObservation:
        self._validate_target(target_id)
        sla_id = str(uuid.uuid4())
        ts = observed_at or time.time()
        details_json = json.dumps(details or {}, sort_keys=True)
        with self._db() as db:
            db.execute(
                """INSERT INTO sla_observations(
                    id, round_id, target_id, service, observed_at, status, latency_ms, source, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (sla_id, round_id, target_id, service, ts, status.value, latency_ms, source, details_json),
            )
        return SlaObservation(
            id=sla_id,
            round_id=round_id,
            target_id=target_id,
            service=service,
            observed_at=ts,
            status=status,
            latency_ms=latency_ms,
            source=source,
            details=details or {},
        )

    def list_sla(
        self, round_id: int | None = None, target_id: str | None = None, limit: int = 100
    ) -> list[SlaObservation]:
        query = "SELECT * FROM sla_observations WHERE 1=1"
        params: list = []
        if round_id is not None:
            query += " AND round_id = ?"
            params.append(round_id)
        if target_id is not None:
            query += " AND target_id = ?"
            params.append(target_id)
        query += " ORDER BY observed_at DESC LIMIT ?"
        params.append(limit)

        with self._db() as db:
            rows = db.execute(query, params).fetchall()
        return [
            SlaObservation(
                id=r["id"],
                round_id=r["round_id"],
                target_id=r["target_id"],
                service=r["service"],
                observed_at=r["observed_at"],
                status=SlaStatus(r["status"]),
                latency_ms=r["latency_ms"],
                source=r["source"],
                details=json.loads(r["details"]),
            )
            for r in rows
        ]

    # --- CHRONOLOGICAL TIMELINE ---

    def get_timeline(
        self, round_id: int | None = None, target_id: str | None = None, limit: int = 50
    ) -> list[TimelineEntry]:
        """Aggregate actions, attacks, defenses, flags, and SLA observations
        into a unified chronological timeline (descending by timestamp).
        """
        entries: list[TimelineEntry] = []

        actions = self.list_actions(round_id=round_id, target_id=target_id, limit=limit)
        for a in actions:
            entries.append(
                TimelineEntry(
                    timestamp=a.timestamp,
                    category=a.category.value.upper(),
                    target_id=a.target_id,
                    item_id=a.id,
                    round_id=a.round_id,
                    title=f"{a.tool} {a.operation}: {a.summary}" if a.tool else a.summary,
                    status=a.status.upper(),
                    details=f"Tool: {a.tool}" if a.tool else "",
                )
            )

        attacks = self.list_attacks(round_id=round_id, target_id=target_id, limit=limit)
        for atk in attacks:
            entries.append(
                TimelineEntry(
                    timestamp=atk.started_at,
                    category="ATTACK",
                    target_id=atk.target_id,
                    item_id=atk.id,
                    round_id=atk.round_id,
                    title=f"{atk.service} via {atk.method}",
                    status=atk.status.value.upper(),
                    details=atk.notes,
                )
            )

        defenses = self.list_defenses(round_id=round_id, target_id=target_id, limit=limit)
        for df in defenses:
            entries.append(
                TimelineEntry(
                    timestamp=df.started_at,
                    category="DEFENSE",
                    target_id=df.target_id,
                    item_id=df.id,
                    round_id=df.round_id,
                    title=f"{df.service}: {df.action}",
                    status=df.status.value.upper(),
                    details=df.notes,
                )
            )

        flags = self.list_flags(round_id=round_id, target_id=target_id, limit=limit)
        for flg in flags:
            entries.append(
                TimelineEntry(
                    timestamp=flg.observed_at,
                    category="FLAG",
                    target_id=flg.target_id,
                    item_id=flg.id,
                    round_id=flg.round_id,
                    title=f"Flag {flg.flag_preview} via {flg.source}",
                    status=flg.status.value.upper(),
                    details=flg.fingerprint,
                )
            )

        sla_obs = self.list_sla(round_id=round_id, target_id=target_id, limit=limit)
        for s in sla_obs:
            lat_str = f"{s.latency_ms:.0f}ms" if s.latency_ms is not None else ""
            entries.append(
                TimelineEntry(
                    timestamp=s.observed_at,
                    category="SLA",
                    target_id=s.target_id,
                    item_id=s.id,
                    round_id=s.round_id,
                    title=f"{s.service} ({s.source}) {lat_str}".strip(),
                    status=s.status.value.upper(),
                    details=f"Source: {s.source}",
                )
            )

        # Deterministic sorting: newest timestamp first, then category, then item_id
        entries.sort(key=lambda x: (x.timestamp, x.category, x.item_id), reverse=True)
        return entries[:limit]
