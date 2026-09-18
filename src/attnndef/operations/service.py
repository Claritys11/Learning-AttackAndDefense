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
    Mission,
    MissionStatus,
    OperatorAction,
    Round,
    RoundStatus,
    Session,
    SessionStatus,
    SlaObservation,
    SlaStatus,
    TimelineEntry,
    Tick,
    WorkflowRun,
    WorkflowStatus,
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

            CREATE TABLE IF NOT EXISTS operational_workflows (
                workflow_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                round_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                objective TEXT NOT NULL DEFAULT '',
                target_id TEXT,
                started_at REAL NOT NULL,
                completed_at REAL,
                status TEXT NOT NULL,
                notes TEXT NOT NULL DEFAULT '',
                FOREIGN KEY(session_id) REFERENCES operational_sessions(session_id) ON DELETE CASCADE,
                FOREIGN KEY(round_id) REFERENCES operational_rounds(round_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS operational_missions (
                mission_id TEXT PRIMARY KEY,
                workflow_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                service_port INTEGER NOT NULL,
                service_protocol TEXT NOT NULL DEFAULT 'tcp',
                title TEXT NOT NULL,
                objective TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                created_at REAL NOT NULL,
                completed_at REAL,
                notes TEXT NOT NULL DEFAULT '',
                initial_observation_id INTEGER,
                FOREIGN KEY(workflow_id) REFERENCES operational_workflows(workflow_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_operator_actions_round ON operator_actions(round_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_operator_actions_target ON operator_actions(target_id);
            CREATE INDEX IF NOT EXISTS idx_attack_records_round ON attack_records(round_id);
            CREATE INDEX IF NOT EXISTS idx_defense_records_round ON defense_records(round_id);
            CREATE INDEX IF NOT EXISTS idx_flag_records_round ON flag_records(round_id);
            CREATE INDEX IF NOT EXISTS idx_sla_obs_target ON sla_observations(target_id, observed_at);
            CREATE INDEX IF NOT EXISTS idx_workflows_session ON operational_workflows(session_id);
            CREATE INDEX IF NOT EXISTS idx_workflows_round ON operational_workflows(round_id);
            CREATE INDEX IF NOT EXISTS idx_workflows_target ON operational_workflows(target_id);
            CREATE INDEX IF NOT EXISTS idx_workflows_status ON operational_workflows(status);
            CREATE INDEX IF NOT EXISTS idx_missions_workflow ON operational_missions(workflow_id);
            CREATE INDEX IF NOT EXISTS idx_missions_target ON operational_missions(target_id);
            CREATE INDEX IF NOT EXISTS idx_missions_status ON operational_missions(status);
            """)

            def _migrate_col(table: str, col: str, col_type: str):
                cur = db.execute(f"PRAGMA table_info({table})")
                cols = [r["name"] for r in cur.fetchall()]
                if col not in cols:
                    db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")

            _migrate_col("operator_actions", "workflow_id", "TEXT")
            _migrate_col("operator_actions", "parent_action_id", "TEXT")
            _migrate_col("operator_actions", "tool_execution_id", "TEXT")
            _migrate_col("operator_actions", "mission_id", "TEXT")
            _migrate_col("attack_records", "workflow_id", "TEXT")
            _migrate_col("attack_records", "mission_id", "TEXT")
            _migrate_col("defense_records", "workflow_id", "TEXT")
            _migrate_col("defense_records", "mission_id", "TEXT")
            _migrate_col("flag_records", "workflow_id", "TEXT")
            _migrate_col("flag_records", "mission_id", "TEXT")
            _migrate_col("sla_observations", "workflow_id", "TEXT")
            _migrate_col("sla_observations", "mission_id", "TEXT")

            db.execute("CREATE INDEX IF NOT EXISTS idx_actions_workflow ON operator_actions(workflow_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_actions_parent ON operator_actions(parent_action_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_actions_mission ON operator_actions(mission_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_attacks_workflow ON attack_records(workflow_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_attacks_mission ON attack_records(mission_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_defenses_workflow ON defense_records(workflow_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_defenses_mission ON defense_records(mission_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_flags_workflow ON flag_records(workflow_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_flags_mission ON flag_records(mission_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_sla_workflow ON sla_observations(workflow_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_sla_mission ON sla_observations(mission_id)")

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
                    session_id = excluded.session_id,
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
        workflow_id: str | None = None,
        parent_action_id: str | None = None,
        tool_execution_id: str | None = None,
        mission_id: str | None = None,
    ) -> OperatorAction:
        self._validate_target(target_id)
        if mission_id:
            mission = self.get_mission(mission_id)
            if not mission:
                raise ValueError(f"Mission not found: {mission_id}")
            if target_id and target_id != mission.target_id:
                raise ValueError(
                    f"Cross-target attachment rejected: action target {target_id} != mission target {mission.target_id}"
                )
            target_id = target_id or mission.target_id
            if workflow_id and workflow_id != mission.workflow_id:
                raise ValueError(
                    f"Cross-workflow attachment rejected: action workflow {workflow_id} != mission workflow {mission.workflow_id}"
                )
            workflow_id = workflow_id or mission.workflow_id
            wf = self.get_workflow(mission.workflow_id)
            if wf and wf.session_id != session_id:
                raise ValueError(
                    f"Cross-session attachment rejected: action session {session_id} != mission session {wf.session_id}"
                )
        if workflow_id:
            wf = self.get_workflow(workflow_id)
            if not wf:
                raise ValueError(f"Workflow not found: {workflow_id}")
            if wf.session_id != session_id:
                raise ValueError(
                    f"Cross-session attachment rejected: action belongs to session {session_id}, workflow to {wf.session_id}"
                )
        if parent_action_id:
            parent = self.get_action(parent_action_id)
            if not parent:
                raise ValueError(f"Parent action not found: {parent_action_id}")

        action_id = str(uuid.uuid4())
        ts = timestamp or time.time()
        details_json = json.dumps(details or {}, sort_keys=True)
        with self._db() as db:
            db.execute(
                """INSERT INTO operator_actions(
                    id, session_id, round_id, timestamp, category, target_id,
                    tool, operation, summary, status, evidence_id, details,
                    workflow_id, parent_action_id, tool_execution_id, mission_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
                    workflow_id,
                    parent_action_id,
                    tool_execution_id,
                    mission_id,
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
            workflow_id=workflow_id,
            parent_action_id=parent_action_id,
            tool_execution_id=tool_execution_id,
            mission_id=mission_id,
        )

    def get_action(self, action_id: str) -> OperatorAction | None:
        with self._db() as db:
            row = db.execute("SELECT * FROM operator_actions WHERE id = ?", (action_id,)).fetchone()
        if not row:
            return None
        keys = row.keys()
        return OperatorAction(
            id=row["id"],
            session_id=row["session_id"],
            round_id=row["round_id"],
            timestamp=row["timestamp"],
            category=ActionCategory(row["category"]),
            target_id=row["target_id"],
            tool=row["tool"],
            operation=row["operation"],
            summary=row["summary"],
            status=row["status"],
            evidence_id=row["evidence_id"],
            details=json.loads(row["details"]),
            workflow_id=row["workflow_id"] if "workflow_id" in keys else None,
            parent_action_id=row["parent_action_id"] if "parent_action_id" in keys else None,
            tool_execution_id=row["tool_execution_id"] if "tool_execution_id" in keys else None,
            mission_id=row["mission_id"] if "mission_id" in keys else None,
        )

    def list_actions(
        self,
        round_id: int | None = None,
        target_id: str | None = None,
        category: ActionCategory | None = None,
        workflow_id: str | None = None,
        mission_id: str | None = None,
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
        if workflow_id is not None:
            query += " AND workflow_id = ?"
            params.append(workflow_id)
        if mission_id is not None:
            query += " AND mission_id = ?"
            params.append(mission_id)
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
                workflow_id=r["workflow_id"] if "workflow_id" in r.keys() else None,
                parent_action_id=r["parent_action_id"] if "parent_action_id" in r.keys() else None,
                tool_execution_id=r["tool_execution_id"] if "tool_execution_id" in r.keys() else None,
                mission_id=r["mission_id"] if "mission_id" in r.keys() else None,
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
        workflow_id: str | None = None,
        started_at: float | None = None,
        mission_id: str | None = None,
    ) -> AttackRecord:
        self._validate_target(target_id)
        if mission_id:
            mission = self.get_mission(mission_id)
            if not mission:
                raise ValueError(f"Mission not found: {mission_id}")
            if target_id != mission.target_id:
                raise ValueError(
                    f"Cross-target attachment rejected: attack target {target_id} != mission target {mission.target_id}"
                )
            if workflow_id and workflow_id != mission.workflow_id:
                raise ValueError(
                    f"Cross-workflow attachment rejected: attack workflow {workflow_id} != mission workflow {mission.workflow_id}"
                )
            workflow_id = workflow_id or mission.workflow_id
            wf = self.get_workflow(mission.workflow_id)
            rnd = self.get_round(round_id)
            if wf and rnd and rnd.session_id != wf.session_id:
                raise ValueError(
                    f"Cross-session attachment rejected: attack round belongs to session {rnd.session_id}, mission workflow to {wf.session_id}"
                )
        if workflow_id:
            wf = self.get_workflow(workflow_id)
            if not wf:
                raise ValueError(f"Workflow not found: {workflow_id}")
            rnd = self.get_round(round_id)
            if rnd and rnd.session_id != wf.session_id:
                raise ValueError(
                    f"Cross-session attachment rejected: attack round belongs to session {rnd.session_id}, workflow to {wf.session_id}"
                )
        attack_id = str(uuid.uuid4())
        started = started_at or time.time()
        with self._db() as db:
            db.execute(
                """INSERT INTO attack_records(
                    id, round_id, target_id, service, method, status, started_at, notes, evidence_id, workflow_id, mission_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (attack_id, round_id, target_id, service, method, status.value, started, notes, evidence_id, workflow_id, mission_id),
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
            workflow_id=workflow_id,
            mission_id=mission_id,
        )

    def get_attack(self, attack_id: str) -> AttackRecord | None:
        with self._db() as db:
            row = db.execute("SELECT * FROM attack_records WHERE id = ?", (attack_id,)).fetchone()
        if not row:
            return None
        keys = row.keys()
        return AttackRecord(
            id=row["id"],
            round_id=row["round_id"],
            target_id=row["target_id"],
            service=row["service"],
            method=row["method"],
            status=AttackStatus(row["status"]),
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            notes=row["notes"],
            evidence_id=row["evidence_id"],
            workflow_id=row["workflow_id"] if "workflow_id" in keys else None,
            mission_id=row["mission_id"] if "mission_id" in keys else None,
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
        self,
        round_id: int | None = None,
        target_id: str | None = None,
        workflow_id: str | None = None,
        mission_id: str | None = None,
        limit: int = 100,
    ) -> list[AttackRecord]:
        query = "SELECT * FROM attack_records WHERE 1=1"
        params: list = []
        if round_id is not None:
            query += " AND round_id = ?"
            params.append(round_id)
        if target_id is not None:
            query += " AND target_id = ?"
            params.append(target_id)
        if workflow_id is not None:
            query += " AND workflow_id = ?"
            params.append(workflow_id)
        if mission_id is not None:
            query += " AND mission_id = ?"
            params.append(mission_id)
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
                workflow_id=r["workflow_id"] if "workflow_id" in r.keys() else None,
                mission_id=r["mission_id"] if "mission_id" in r.keys() else None,
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
        workflow_id: str | None = None,
        started_at: float | None = None,
        mission_id: str | None = None,
    ) -> DefenseRecord:
        self._validate_target(target_id)
        if mission_id:
            mission = self.get_mission(mission_id)
            if not mission:
                raise ValueError(f"Mission not found: {mission_id}")
            if target_id != mission.target_id:
                raise ValueError(
                    f"Cross-target attachment rejected: defense target {target_id} != mission target {mission.target_id}"
                )
            if workflow_id and workflow_id != mission.workflow_id:
                raise ValueError(
                    f"Cross-workflow attachment rejected: defense workflow {workflow_id} != mission workflow {mission.workflow_id}"
                )
            workflow_id = workflow_id or mission.workflow_id
            wf = self.get_workflow(mission.workflow_id)
            rnd = self.get_round(round_id)
            if wf and rnd and rnd.session_id != wf.session_id:
                raise ValueError(
                    f"Cross-session attachment rejected: defense round belongs to session {rnd.session_id}, mission workflow to {wf.session_id}"
                )
        if workflow_id:
            wf = self.get_workflow(workflow_id)
            if not wf:
                raise ValueError(f"Workflow not found: {workflow_id}")
            rnd = self.get_round(round_id)
            if rnd and rnd.session_id != wf.session_id:
                raise ValueError(
                    f"Cross-session attachment rejected: defense round belongs to session {rnd.session_id}, workflow to {wf.session_id}"
                )
        defense_id = str(uuid.uuid4())
        started = started_at or time.time()
        with self._db() as db:
            db.execute(
                """INSERT INTO defense_records(
                    id, round_id, target_id, service, action, status, started_at, notes, evidence_id, workflow_id, mission_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (defense_id, round_id, target_id, service, action, status.value, started, notes, evidence_id, workflow_id, mission_id),
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
            workflow_id=workflow_id,
            mission_id=mission_id,
        )

    def get_defense(self, defense_id: str) -> DefenseRecord | None:
        with self._db() as db:
            row = db.execute("SELECT * FROM defense_records WHERE id = ?", (defense_id,)).fetchone()
        if not row:
            return None
        keys = row.keys()
        return DefenseRecord(
            id=row["id"],
            round_id=row["round_id"],
            target_id=row["target_id"],
            service=row["service"],
            action=row["action"],
            status=DefenseStatus(row["status"]),
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            notes=row["notes"],
            evidence_id=row["evidence_id"],
            workflow_id=row["workflow_id"] if "workflow_id" in keys else None,
            mission_id=row["mission_id"] if "mission_id" in keys else None,
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
        self,
        round_id: int | None = None,
        target_id: str | None = None,
        workflow_id: str | None = None,
        mission_id: str | None = None,
        limit: int = 100,
    ) -> list[DefenseRecord]:
        query = "SELECT * FROM defense_records WHERE 1=1"
        params: list = []
        if round_id is not None:
            query += " AND round_id = ?"
            params.append(round_id)
        if target_id is not None:
            query += " AND target_id = ?"
            params.append(target_id)
        if workflow_id is not None:
            query += " AND workflow_id = ?"
            params.append(workflow_id)
        if mission_id is not None:
            query += " AND mission_id = ?"
            params.append(mission_id)
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
                workflow_id=r["workflow_id"] if "workflow_id" in r.keys() else None,
                mission_id=r["mission_id"] if "mission_id" in r.keys() else None,
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
        workflow_id: str | None = None,
        observed_at: float | None = None,
        mission_id: str | None = None,
    ) -> FlagRecord:
        self._validate_target(target_id)
        if mission_id:
            mission = self.get_mission(mission_id)
            if not mission:
                raise ValueError(f"Mission not found: {mission_id}")
            if target_id != mission.target_id:
                raise ValueError(
                    f"Cross-target attachment rejected: flag target {target_id} != mission target {mission.target_id}"
                )
            if workflow_id and workflow_id != mission.workflow_id:
                raise ValueError(
                    f"Cross-workflow attachment rejected: flag workflow {workflow_id} != mission workflow {mission.workflow_id}"
                )
            workflow_id = workflow_id or mission.workflow_id
            wf = self.get_workflow(mission.workflow_id)
            rnd = self.get_round(round_id)
            if wf and rnd and rnd.session_id != wf.session_id:
                raise ValueError(
                    f"Cross-session attachment rejected: flag round belongs to session {rnd.session_id}, mission workflow to {wf.session_id}"
                )
        if workflow_id:
            wf = self.get_workflow(workflow_id)
            if not wf:
                raise ValueError(f"Workflow not found: {workflow_id}")
            rnd = self.get_round(round_id)
            if rnd and rnd.session_id != wf.session_id:
                raise ValueError(
                    f"Cross-session attachment rejected: flag round belongs to session {rnd.session_id}, workflow to {wf.session_id}"
                )
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
                    fingerprint, flag_preview, notes, evidence_id, workflow_id, mission_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
                    workflow_id,
                    mission_id,
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
            workflow_id=workflow_id,
            mission_id=mission_id,
        )

    def get_flag(self, flag_id: str) -> FlagRecord | None:
        with self._db() as db:
            row = db.execute("SELECT * FROM flag_records WHERE id = ?", (flag_id,)).fetchone()
        if not row:
            return None
        keys = row.keys()
        return FlagRecord(
            id=row["id"],
            round_id=row["round_id"],
            target_id=row["target_id"],
            source=row["source"],
            observed_at=row["observed_at"],
            status=FlagStatus(row["status"]),
            fingerprint=row["fingerprint"],
            flag_preview=row["flag_preview"],
            notes=row["notes"],
            evidence_id=row["evidence_id"],
            workflow_id=row["workflow_id"] if "workflow_id" in keys else None,
            mission_id=row["mission_id"] if "mission_id" in keys else None,
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
        self,
        round_id: int | None = None,
        target_id: str | None = None,
        workflow_id: str | None = None,
        mission_id: str | None = None,
        limit: int = 100,
    ) -> list[FlagRecord]:
        query = "SELECT * FROM flag_records WHERE 1=1"
        params: list = []
        if round_id is not None:
            query += " AND round_id = ?"
            params.append(round_id)
        if target_id is not None:
            query += " AND target_id = ?"
            params.append(target_id)
        if workflow_id is not None:
            query += " AND workflow_id = ?"
            params.append(workflow_id)
        if mission_id is not None:
            query += " AND mission_id = ?"
            params.append(mission_id)
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
                workflow_id=r["workflow_id"] if "workflow_id" in r.keys() else None,
                mission_id=r["mission_id"] if "mission_id" in r.keys() else None,
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
        workflow_id: str | None = None,
        observed_at: float | None = None,
        mission_id: str | None = None,
    ) -> SlaObservation:
        self._validate_target(target_id)
        if mission_id:
            mission = self.get_mission(mission_id)
            if not mission:
                raise ValueError(f"Mission not found: {mission_id}")
            if target_id != mission.target_id:
                raise ValueError(
                    f"Cross-target attachment rejected: SLA target {target_id} != mission target {mission.target_id}"
                )
            if workflow_id and workflow_id != mission.workflow_id:
                raise ValueError(
                    f"Cross-workflow attachment rejected: SLA workflow {workflow_id} != mission workflow {mission.workflow_id}"
                )
            workflow_id = workflow_id or mission.workflow_id
            wf = self.get_workflow(mission.workflow_id)
            rnd = self.get_round(round_id)
            if wf and rnd and rnd.session_id != wf.session_id:
                raise ValueError(
                    f"Cross-session attachment rejected: SLA round belongs to session {rnd.session_id}, mission workflow to {wf.session_id}"
                )
        if workflow_id:
            wf = self.get_workflow(workflow_id)
            if not wf:
                raise ValueError(f"Workflow not found: {workflow_id}")
            rnd = self.get_round(round_id)
            if rnd and rnd.session_id != wf.session_id:
                raise ValueError(
                    f"Cross-session attachment rejected: SLA round belongs to session {rnd.session_id}, workflow to {wf.session_id}"
                )
        sla_id = str(uuid.uuid4())
        ts = observed_at or time.time()
        details_json = json.dumps(details or {}, sort_keys=True)
        with self._db() as db:
            db.execute(
                """INSERT INTO sla_observations(
                    id, round_id, target_id, service, observed_at, status, latency_ms, source, details, workflow_id, mission_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (sla_id, round_id, target_id, service, ts, status.value, latency_ms, source, details_json, workflow_id, mission_id),
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
            workflow_id=workflow_id,
            mission_id=mission_id,
        )

    def get_sla(self, sla_id: str) -> SlaObservation | None:
        with self._db() as db:
            row = db.execute("SELECT * FROM sla_observations WHERE id = ?", (sla_id,)).fetchone()
        if not row:
            return None
        keys = row.keys()
        return SlaObservation(
            id=row["id"],
            round_id=row["round_id"],
            target_id=row["target_id"],
            service=row["service"],
            observed_at=row["observed_at"],
            status=SlaStatus(row["status"]),
            latency_ms=row["latency_ms"],
            source=row["source"],
            details=json.loads(row["details"]),
            workflow_id=row["workflow_id"] if "workflow_id" in keys else None,
            mission_id=row["mission_id"] if "mission_id" in keys else None,
        )

    def list_sla(
        self,
        round_id: int | None = None,
        target_id: str | None = None,
        workflow_id: str | None = None,
        mission_id: str | None = None,
        limit: int = 100,
    ) -> list[SlaObservation]:
        query = "SELECT * FROM sla_observations WHERE 1=1"
        params: list = []
        if round_id is not None:
            query += " AND round_id = ?"
            params.append(round_id)
        if target_id is not None:
            query += " AND target_id = ?"
            params.append(target_id)
        if workflow_id is not None:
            query += " AND workflow_id = ?"
            params.append(workflow_id)
        if mission_id is not None:
            query += " AND mission_id = ?"
            params.append(mission_id)
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
                workflow_id=r["workflow_id"] if "workflow_id" in r.keys() else None,
                mission_id=r["mission_id"] if "mission_id" in r.keys() else None,
            )
            for r in rows
        ]

    # --- WORKFLOWS ---

    def create_workflow(
        self,
        session_id: str,
        round_id: int,
        title: str,
        objective: str = "",
        target_id: str | None = None,
        notes: str = "",
        started_at: float | None = None,
    ) -> WorkflowRun:
        session = self.get_session(session_id)
        if not session:
            raise ValueError(f"Session not found: {session_id}")
        rnd = self.get_round(round_id)
        if not rnd:
            raise ValueError(f"Round not found: {round_id}")
        if rnd.session_id != session_id:
            raise ValueError(f"Round {round_id} belongs to session {rnd.session_id}, not {session_id}")
        self._validate_target(target_id)

        workflow_id = str(uuid.uuid4())
        started = started_at or time.time()
        with self._db() as db:
            db.execute(
                """INSERT INTO operational_workflows(
                    workflow_id, session_id, round_id, title, objective, target_id, started_at, status, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    workflow_id,
                    session_id,
                    round_id,
                    title,
                    objective,
                    target_id,
                    started,
                    WorkflowStatus.ACTIVE.value,
                    notes,
                ),
            )
        return WorkflowRun(
            workflow_id=workflow_id,
            session_id=session_id,
            round_id=round_id,
            title=title,
            objective=objective,
            target_id=target_id,
            started_at=started,
            status=WorkflowStatus.ACTIVE,
            notes=notes,
        )

    def get_workflow(self, workflow_id: str) -> WorkflowRun | None:
        with self._db() as db:
            row = db.execute("SELECT * FROM operational_workflows WHERE workflow_id = ?", (workflow_id,)).fetchone()
        if not row:
            return None
        return WorkflowRun(
            workflow_id=row["workflow_id"],
            session_id=row["session_id"],
            round_id=row["round_id"],
            title=row["title"],
            objective=row["objective"],
            target_id=row["target_id"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            status=WorkflowStatus(row["status"]),
            notes=row["notes"],
        )

    def list_workflows(
        self,
        session_id: str | None = None,
        round_id: int | None = None,
        status: WorkflowStatus | None = None,
        target_id: str | None = None,
        limit: int = 100,
    ) -> list[WorkflowRun]:
        query = "SELECT * FROM operational_workflows WHERE 1=1"
        params: list = []
        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)
        if round_id is not None:
            query += " AND round_id = ?"
            params.append(round_id)
        if status is not None:
            query += " AND status = ?"
            params.append(status.value)
        if target_id:
            query += " AND target_id = ?"
            params.append(target_id)
        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)

        with self._db() as db:
            rows = db.execute(query, params).fetchall()
        return [
            WorkflowRun(
                workflow_id=r["workflow_id"],
                session_id=r["session_id"],
                round_id=r["round_id"],
                title=r["title"],
                objective=r["objective"],
                target_id=r["target_id"],
                started_at=r["started_at"],
                completed_at=r["completed_at"],
                status=WorkflowStatus(r["status"]),
                notes=r["notes"],
            )
            for r in rows
        ]

    def complete_workflow(self, workflow_id: str, notes: str | None = None) -> bool:
        now = time.time()
        wf = self.get_workflow(workflow_id)
        if not wf:
            raise ValueError(f"Workflow not found: {workflow_id}")
        if wf.status != WorkflowStatus.ACTIVE:
            raise ValueError(f"Cannot complete workflow in state {wf.status.value}")
        new_notes = notes if notes is not None else wf.notes
        with self._db() as db:
            cur = db.execute(
                "UPDATE operational_workflows SET status = ?, completed_at = ?, notes = ? WHERE workflow_id = ?",
                (WorkflowStatus.COMPLETED.value, now, new_notes, workflow_id),
            )
        return cur.rowcount > 0

    def abort_workflow(self, workflow_id: str, notes: str | None = None) -> bool:
        now = time.time()
        wf = self.get_workflow(workflow_id)
        if not wf:
            raise ValueError(f"Workflow not found: {workflow_id}")
        if wf.status != WorkflowStatus.ACTIVE:
            raise ValueError(f"Cannot abort workflow in state {wf.status.value}")
        new_notes = notes if notes is not None else wf.notes
        with self._db() as db:
            cur = db.execute(
                "UPDATE operational_workflows SET status = ?, completed_at = ?, notes = ? WHERE workflow_id = ?",
                (WorkflowStatus.ABORTED.value, now, new_notes, workflow_id),
            )
        return cur.rowcount > 0

    def attach_action_to_workflow(self, action_id: str, workflow_id: str) -> bool:
        wf = self.get_workflow(workflow_id)
        if not wf:
            raise ValueError(f"Workflow not found: {workflow_id}")
        action = self.get_action(action_id)
        if not action:
            raise ValueError(f"Action not found: {action_id}")
        if action.session_id != wf.session_id:
            raise ValueError(
                f"Cross-session attachment rejected: action belongs to session {action.session_id}, workflow to {wf.session_id}"
            )
        with self._db() as db:
            cur = db.execute("UPDATE operator_actions SET workflow_id = ? WHERE id = ?", (workflow_id, action_id))
        return cur.rowcount > 0

    def attach_attack_to_workflow(self, attack_id: str, workflow_id: str) -> bool:
        wf = self.get_workflow(workflow_id)
        if not wf:
            raise ValueError(f"Workflow not found: {workflow_id}")
        atk = self.get_attack(attack_id)
        if not atk:
            raise ValueError(f"Attack not found: {attack_id}")
        rnd = self.get_round(atk.round_id)
        if rnd and rnd.session_id != wf.session_id:
            raise ValueError(
                f"Cross-session attachment rejected: attack round belongs to session {rnd.session_id}, workflow to {wf.session_id}"
            )
        with self._db() as db:
            cur = db.execute("UPDATE attack_records SET workflow_id = ? WHERE id = ?", (workflow_id, attack_id))
        return cur.rowcount > 0

    def attach_defense_to_workflow(self, defense_id: str, workflow_id: str) -> bool:
        wf = self.get_workflow(workflow_id)
        if not wf:
            raise ValueError(f"Workflow not found: {workflow_id}")
        df = self.get_defense(defense_id)
        if not df:
            raise ValueError(f"Defense not found: {defense_id}")
        rnd = self.get_round(df.round_id)
        if rnd and rnd.session_id != wf.session_id:
            raise ValueError(
                f"Cross-session attachment rejected: defense round belongs to session {rnd.session_id}, workflow to {wf.session_id}"
            )
        with self._db() as db:
            cur = db.execute("UPDATE defense_records SET workflow_id = ? WHERE id = ?", (workflow_id, defense_id))
        return cur.rowcount > 0

    def attach_flag_to_workflow(self, flag_id: str, workflow_id: str) -> bool:
        wf = self.get_workflow(workflow_id)
        if not wf:
            raise ValueError(f"Workflow not found: {workflow_id}")
        flg = self.get_flag(flag_id)
        if not flg:
            raise ValueError(f"Flag record not found: {flag_id}")
        rnd = self.get_round(flg.round_id)
        if rnd and rnd.session_id != wf.session_id:
            raise ValueError(
                f"Cross-session attachment rejected: flag round belongs to session {rnd.session_id}, workflow to {wf.session_id}"
            )
        with self._db() as db:
            cur = db.execute("UPDATE flag_records SET workflow_id = ? WHERE id = ?", (workflow_id, flag_id))
        return cur.rowcount > 0

    def attach_sla_to_workflow(self, sla_id: str, workflow_id: str) -> bool:
        wf = self.get_workflow(workflow_id)
        if not wf:
            raise ValueError(f"Workflow not found: {workflow_id}")
        sla = self.get_sla(sla_id)
        if not sla:
            raise ValueError(f"SLA observation not found: {sla_id}")
        rnd = self.get_round(sla.round_id)
        if rnd and rnd.session_id != wf.session_id:
            raise ValueError(
                f"Cross-session attachment rejected: SLA round belongs to session {rnd.session_id}, workflow to {wf.session_id}"
            )
        with self._db() as db:
            cur = db.execute("UPDATE sla_observations SET workflow_id = ? WHERE id = ?", (workflow_id, sla_id))
        return cur.rowcount > 0

    # --- MISSIONS ---

    def create_mission(
        self,
        workflow_id: str,
        target_id: str,
        service_port: int,
        title: str,
        *,
        service_protocol: str = "tcp",
        objective: str = "",
        notes: str = "",
        initial_observation_id: int | None = None,
        mission_id: str | None = None,
    ) -> Mission:
        wf = self.get_workflow(workflow_id)
        if not wf:
            raise ValueError(f"Workflow not found: {workflow_id}")
        self._validate_target(target_id)
        if not (1 <= service_port <= 65535):
            raise ValueError(f"Invalid service port: {service_port} (must be between 1 and 65535)")
        service_protocol = service_protocol.lower().strip()
        if service_protocol not in ("tcp", "udp"):
            raise ValueError(f"Invalid service protocol: {service_protocol} (must be 'tcp' or 'udp')")

        if initial_observation_id is not None and self.target_service is not None:
            hist = self.target_service.history(target_id, limit=200)
            matched_obs = next((o for o in hist if o.id == initial_observation_id), None)
            if not matched_obs:
                raise ValueError(f"Observation {initial_observation_id} not found for target {target_id}")
            has_service = any(
                s.port == service_port and s.protocol.lower() == service_protocol
                for s in matched_obs.services
            )
            if not has_service:
                raise ValueError(
                    f"Service {service_protocol.upper()}:{service_port} not found in observation #{initial_observation_id}"
                )

        mid = mission_id or str(uuid.uuid4())
        now = time.time()
        with self._db() as db:
            db.execute(
                """INSERT INTO operational_missions(
                    mission_id, workflow_id, target_id, service_port, service_protocol,
                    title, objective, status, created_at, notes, initial_observation_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    mid,
                    workflow_id,
                    target_id,
                    service_port,
                    service_protocol,
                    title,
                    objective,
                    MissionStatus.OPEN.value,
                    now,
                    notes,
                    initial_observation_id,
                ),
            )
        return Mission(
            mission_id=mid,
            workflow_id=workflow_id,
            target_id=target_id,
            service_port=service_port,
            service_protocol=service_protocol,
            title=title,
            objective=objective,
            status=MissionStatus.OPEN,
            created_at=now,
            notes=notes,
            initial_observation_id=initial_observation_id,
        )

    def get_mission(self, mission_id: str) -> Mission | None:
        with self._db() as db:
            row = db.execute("SELECT * FROM operational_missions WHERE mission_id = ?", (mission_id,)).fetchone()
        if not row:
            return None
        return Mission(
            mission_id=row["mission_id"],
            workflow_id=row["workflow_id"],
            target_id=row["target_id"],
            service_port=row["service_port"],
            service_protocol=row["service_protocol"],
            title=row["title"],
            objective=row["objective"],
            status=MissionStatus(row["status"]),
            created_at=row["created_at"],
            completed_at=row["completed_at"],
            notes=row["notes"],
            initial_observation_id=row["initial_observation_id"],
        )

    def list_missions(
        self,
        workflow_id: str | None = None,
        target_id: str | None = None,
        status: MissionStatus | None = None,
        limit: int = 100,
    ) -> list[Mission]:
        query = "SELECT * FROM operational_missions WHERE 1=1"
        params: list = []
        if workflow_id:
            query += " AND workflow_id = ?"
            params.append(workflow_id)
        if target_id:
            query += " AND target_id = ?"
            params.append(target_id)
        if status is not None:
            query += " AND status = ?"
            params.append(status.value)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self._db() as db:
            rows = db.execute(query, params).fetchall()
        return [
            Mission(
                mission_id=r["mission_id"],
                workflow_id=r["workflow_id"],
                target_id=r["target_id"],
                service_port=r["service_port"],
                service_protocol=r["service_protocol"],
                title=r["title"],
                objective=r["objective"],
                status=MissionStatus(r["status"]),
                created_at=r["created_at"],
                completed_at=r["completed_at"],
                notes=r["notes"],
                initial_observation_id=r["initial_observation_id"],
            )
            for r in rows
        ]

    def start_mission(self, mission_id: str) -> bool:
        m = self.get_mission(mission_id)
        if not m:
            raise ValueError(f"Mission not found: {mission_id}")
        if m.status in (MissionStatus.COMPLETED, MissionStatus.ABORTED):
            raise ValueError(f"Cannot start mission in terminal status: {m.status.value}")
        if m.status == MissionStatus.IN_PROGRESS:
            return True
        with self._db() as db:
            cur = db.execute(
                "UPDATE operational_missions SET status = ? WHERE mission_id = ?",
                (MissionStatus.IN_PROGRESS.value, mission_id),
            )
        return cur.rowcount > 0

    def complete_mission(self, mission_id: str, notes: str | None = None) -> bool:
        now = time.time()
        m = self.get_mission(mission_id)
        if not m:
            raise ValueError(f"Mission not found: {mission_id}")
        if m.status == MissionStatus.COMPLETED:
            return True
        if m.status == MissionStatus.ABORTED:
            raise ValueError("Cannot complete aborted mission")
        new_notes = notes if notes is not None else m.notes
        with self._db() as db:
            cur = db.execute(
                "UPDATE operational_missions SET status = ?, completed_at = ?, notes = ? WHERE mission_id = ?",
                (MissionStatus.COMPLETED.value, now, new_notes, mission_id),
            )
        return cur.rowcount > 0

    def abort_mission(self, mission_id: str, notes: str | None = None) -> bool:
        now = time.time()
        m = self.get_mission(mission_id)
        if not m:
            raise ValueError(f"Mission not found: {mission_id}")
        if m.status == MissionStatus.ABORTED:
            return True
        if m.status == MissionStatus.COMPLETED:
            raise ValueError("Cannot abort completed mission")
        new_notes = notes if notes is not None else m.notes
        with self._db() as db:
            cur = db.execute(
                "UPDATE operational_missions SET status = ?, completed_at = ?, notes = ? WHERE mission_id = ?",
                (MissionStatus.ABORTED.value, now, new_notes, mission_id),
            )
        return cur.rowcount > 0

    def attach_action_to_mission(self, action_id: str, mission_id: str) -> bool:
        m = self.get_mission(mission_id)
        if not m:
            raise ValueError(f"Mission not found: {mission_id}")
        action = self.get_action(action_id)
        if not action:
            raise ValueError(f"Action not found: {action_id}")
        if action.mission_id and action.mission_id != mission_id:
            raise ValueError(
                f"Conflicting mission reassignment rejected: action already assigned to mission {action.mission_id}"
            )
        if action.target_id and action.target_id != m.target_id:
            raise ValueError(
                f"Cross-target attachment rejected: action target {action.target_id} != mission target {m.target_id}"
            )
        if action.workflow_id and action.workflow_id != m.workflow_id:
            raise ValueError(
                f"Cross-workflow attachment rejected: action workflow {action.workflow_id} != mission workflow {m.workflow_id}"
            )
        wf = self.get_workflow(m.workflow_id)
        if wf and action.session_id != wf.session_id:
            raise ValueError(
                f"Cross-session attachment rejected: action belongs to session {action.session_id}, mission workflow to {wf.session_id}"
            )
        with self._db() as db:
            cur = db.execute(
                "UPDATE operator_actions SET mission_id = ? WHERE id = ?",
                (mission_id, action_id),
            )
        return cur.rowcount > 0

    def attach_attack_to_mission(self, attack_id: str, mission_id: str) -> bool:
        m = self.get_mission(mission_id)
        if not m:
            raise ValueError(f"Mission not found: {mission_id}")
        atk = self.get_attack(attack_id)
        if not atk:
            raise ValueError(f"Attack not found: {attack_id}")
        if atk.mission_id and atk.mission_id != mission_id:
            raise ValueError(
                f"Conflicting mission reassignment rejected: attack already assigned to mission {atk.mission_id}"
            )
        if atk.target_id != m.target_id:
            raise ValueError(
                f"Cross-target attachment rejected: attack target {atk.target_id} != mission target {m.target_id}"
            )
        if atk.workflow_id and atk.workflow_id != m.workflow_id:
            raise ValueError(
                f"Cross-workflow attachment rejected: attack workflow {atk.workflow_id} != mission workflow {m.workflow_id}"
            )
        wf = self.get_workflow(m.workflow_id)
        rnd = self.get_round(atk.round_id)
        if wf and rnd and rnd.session_id != wf.session_id:
            raise ValueError(
                f"Cross-session attachment rejected: attack round belongs to session {rnd.session_id}, mission workflow to {wf.session_id}"
            )
        with self._db() as db:
            cur = db.execute(
                "UPDATE attack_records SET mission_id = ? WHERE id = ?",
                (mission_id, attack_id),
            )
        return cur.rowcount > 0

    def attach_defense_to_mission(self, defense_id: str, mission_id: str) -> bool:
        m = self.get_mission(mission_id)
        if not m:
            raise ValueError(f"Mission not found: {mission_id}")
        df = self.get_defense(defense_id)
        if not df:
            raise ValueError(f"Defense not found: {defense_id}")
        if df.mission_id and df.mission_id != mission_id:
            raise ValueError(
                f"Conflicting mission reassignment rejected: defense already assigned to mission {df.mission_id}"
            )
        if df.target_id != m.target_id:
            raise ValueError(
                f"Cross-target attachment rejected: defense target {df.target_id} != mission target {m.target_id}"
            )
        if df.workflow_id and df.workflow_id != m.workflow_id:
            raise ValueError(
                f"Cross-workflow attachment rejected: defense workflow {df.workflow_id} != mission workflow {m.workflow_id}"
            )
        wf = self.get_workflow(m.workflow_id)
        rnd = self.get_round(df.round_id)
        if wf and rnd and rnd.session_id != wf.session_id:
            raise ValueError(
                f"Cross-session attachment rejected: defense round belongs to session {rnd.session_id}, mission workflow to {wf.session_id}"
            )
        with self._db() as db:
            cur = db.execute(
                "UPDATE defense_records SET mission_id = ? WHERE id = ?",
                (mission_id, defense_id),
            )
        return cur.rowcount > 0

    def attach_flag_to_mission(self, flag_id: str, mission_id: str) -> bool:
        m = self.get_mission(mission_id)
        if not m:
            raise ValueError(f"Mission not found: {mission_id}")
        flg = self.get_flag(flag_id)
        if not flg:
            raise ValueError(f"Flag record not found: {flag_id}")
        if flg.mission_id and flg.mission_id != mission_id:
            raise ValueError(
                f"Conflicting mission reassignment rejected: flag already assigned to mission {flg.mission_id}"
            )
        if flg.target_id != m.target_id:
            raise ValueError(
                f"Cross-target attachment rejected: flag target {flg.target_id} != mission target {m.target_id}"
            )
        if flg.workflow_id and flg.workflow_id != m.workflow_id:
            raise ValueError(
                f"Cross-workflow attachment rejected: flag workflow {flg.workflow_id} != mission workflow {m.workflow_id}"
            )
        wf = self.get_workflow(m.workflow_id)
        rnd = self.get_round(flg.round_id)
        if wf and rnd and rnd.session_id != wf.session_id:
            raise ValueError(
                f"Cross-session attachment rejected: flag round belongs to session {rnd.session_id}, mission workflow to {wf.session_id}"
            )
        with self._db() as db:
            cur = db.execute(
                "UPDATE flag_records SET mission_id = ? WHERE id = ?",
                (mission_id, flag_id),
            )
        return cur.rowcount > 0

    def attach_sla_to_mission(self, sla_id: str, mission_id: str) -> bool:
        m = self.get_mission(mission_id)
        if not m:
            raise ValueError(f"Mission not found: {mission_id}")
        sla = self.get_sla(sla_id)
        if not sla:
            raise ValueError(f"SLA observation not found: {sla_id}")
        if sla.mission_id and sla.mission_id != mission_id:
            raise ValueError(
                f"Conflicting mission reassignment rejected: SLA observation already assigned to mission {sla.mission_id}"
            )
        if sla.target_id != m.target_id:
            raise ValueError(
                f"Cross-target attachment rejected: SLA target {sla.target_id} != mission target {m.target_id}"
            )
        if sla.workflow_id and sla.workflow_id != m.workflow_id:
            raise ValueError(
                f"Cross-workflow attachment rejected: SLA workflow {sla.workflow_id} != mission workflow {m.workflow_id}"
            )
        wf = self.get_workflow(m.workflow_id)
        rnd = self.get_round(sla.round_id)
        if wf and rnd and rnd.session_id != wf.session_id:
            raise ValueError(
                f"Cross-session attachment rejected: SLA round belongs to session {rnd.session_id}, mission workflow to {wf.session_id}"
            )
        with self._db() as db:
            cur = db.execute(
                "UPDATE sla_observations SET mission_id = ? WHERE id = ?",
                (mission_id, sla_id),
            )
        return cur.rowcount > 0

    # --- CHRONOLOGICAL TIMELINE ---

    def get_timeline(
        self,
        round_id: int | None = None,
        target_id: str | None = None,
        workflow_id: str | None = None,
        mission_id: str | None = None,
        limit: int = 50,
    ) -> list[TimelineEntry]:
        """Aggregate actions, attacks, defenses, flags, and SLA observations
        into a unified chronological timeline (descending by timestamp).
        """
        entries: list[TimelineEntry] = []

        actions = self.list_actions(
            round_id=round_id,
            target_id=target_id,
            workflow_id=workflow_id,
            mission_id=mission_id,
            limit=limit,
        )
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
                    workflow_id=a.workflow_id,
                    mission_id=a.mission_id,
                )
            )

        attacks = self.list_attacks(
            round_id=round_id,
            target_id=target_id,
            workflow_id=workflow_id,
            mission_id=mission_id,
            limit=limit,
        )
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
                    workflow_id=atk.workflow_id,
                    mission_id=atk.mission_id,
                )
            )

        defenses = self.list_defenses(
            round_id=round_id,
            target_id=target_id,
            workflow_id=workflow_id,
            mission_id=mission_id,
            limit=limit,
        )
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
                    workflow_id=df.workflow_id,
                    mission_id=df.mission_id,
                )
            )

        flags = self.list_flags(
            round_id=round_id,
            target_id=target_id,
            workflow_id=workflow_id,
            mission_id=mission_id,
            limit=limit,
        )
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
                    workflow_id=flg.workflow_id,
                    mission_id=flg.mission_id,
                )
            )

        sla_obs = self.list_sla(
            round_id=round_id,
            target_id=target_id,
            workflow_id=workflow_id,
            mission_id=mission_id,
            limit=limit,
        )
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
                    workflow_id=s.workflow_id,
                    mission_id=s.mission_id,
                )
            )

        # Deterministic sorting: newest timestamp first, then category, then item_id
        entries.sort(key=lambda x: (x.timestamp, x.category, x.item_id), reverse=True)
        return entries[:limit]

    def get_workflow_timeline(self, workflow_id: str, limit: int = 100) -> list[TimelineEntry]:
        """Aggregate all records associated with a workflow into a chronological
        story timeline (ascending by timestamp: earliest to latest).
        """
        wf = self.get_workflow(workflow_id)
        if not wf:
            raise ValueError(f"Workflow not found: {workflow_id}")

        entries = self.get_timeline(workflow_id=workflow_id, limit=limit)
        # Sort ascending for workflow progression: earliest to latest
        entries.sort(key=lambda x: (x.timestamp, x.category, x.item_id))
        return entries

    def get_mission_timeline(self, mission_id: str, limit: int = 100) -> list[TimelineEntry]:
        """Aggregate all records associated with a mission into a chronological
        story timeline (ascending by timestamp: earliest to latest).
        """
        m = self.get_mission(mission_id)
        if not m:
            raise ValueError(f"Mission not found: {mission_id}")

        entries = self.get_timeline(mission_id=mission_id, limit=limit)
        # Sort ascending for mission progression: earliest to latest
        entries.sort(key=lambda x: (x.timestamp, x.category, x.item_id))
        return entries
