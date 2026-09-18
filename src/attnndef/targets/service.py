from __future__ import annotations
import json
import sqlite3
import time
from dataclasses import asdict
from pathlib import Path
from .models import Observation, Role, Service, Target

class TargetService:
    """SQLite-backed target intelligence service shared by UI and future CLI."""
    def __init__(self, db_path: str | Path):
        self.path = Path(db_path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _db(self):
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def _init(self):
        with self._db() as db:
            db.execute("PRAGMA foreign_keys = ON")
            db.executescript("""
            CREATE TABLE IF NOT EXISTS targets (
              id TEXT PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL,
              role TEXT NOT NULL, tags TEXT NOT NULL, notes TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS observations (
              id INTEGER PRIMARY KEY AUTOINCREMENT, target_id TEXT NOT NULL,
              observed_at REAL NOT NULL, session_id TEXT NOT NULL, round_id INTEGER,
              services TEXT NOT NULL, fingerprint TEXT NOT NULL, status TEXT NOT NULL,
              details TEXT NOT NULL
            );
            """)

    def add_target(self, target: Target) -> Target:
        with self._db() as db:
            db.execute("INSERT INTO targets(id,name,host,role,tags,notes) VALUES(?,?,?,?,?,?)", (target.id, target.name, target.host, target.role.value, json.dumps(target.tags), target.notes))
        return target

    def upsert_target(self, target: Target) -> Target:
        with self._db() as db:
            db.execute("INSERT INTO targets(id,name,host,role,tags,notes) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,host=excluded.host,role=excluded.role,tags=excluded.tags,notes=excluded.notes", (target.id, target.name, target.host, target.role.value, json.dumps(target.tags), target.notes))
        return target

    def update_target(self, target_id: str, *, name: str | None = None, host: str | None = None, role: Role | None = None, tags: tuple[str, ...] | None = None, notes: str | None = None) -> Target:
        current = self.get_target(target_id)
        if current is None:
            raise ValueError(f"unknown target: {target_id}")
        updated = Target(target_id, name if name is not None else current.name, host if host is not None else current.host, role if role is not None else current.role, tags if tags is not None else current.tags, notes if notes is not None else current.notes)
        return self.upsert_target(updated)

    def get_target(self, target_id: str) -> Target | None:
        with self._db() as db: row = db.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
        return self._target(row) if row else None

    def list_targets(self, role: Role | None = None) -> list[Target]:
        query, params = "SELECT * FROM targets", ()
        if role is not None: query += " WHERE role=?"; params = (role.value,)
        with self._db() as db: rows = db.execute(query + " ORDER BY id", params).fetchall()
        return [self._target(row) for row in rows]

    def remove_target(self, target_id: str) -> bool:
        with self._db() as db:
            db.execute("PRAGMA foreign_keys = ON")
            cur = db.execute("DELETE FROM targets WHERE id=?", (target_id,))
        return cur.rowcount == 1

    def record_observation(self, observation: Observation) -> Observation:
        if self.get_target(observation.target_id) is None:
            raise ValueError(f"unknown target: {observation.target_id}")
        with self._db() as db:
            cur = db.execute("INSERT INTO observations(target_id,observed_at,session_id,round_id,services,fingerprint,status,details) VALUES(?,?,?,?,?,?,?,?)", (observation.target_id, observation.observed_at, observation.session_id, observation.round_id, json.dumps([asdict(s) for s in observation.services]), observation.fingerprint, observation.status, json.dumps(observation.details)))
        return Observation(cur.lastrowid, observation.target_id, observation.observed_at, observation.session_id, observation.round_id, observation.services, observation.fingerprint, observation.status, observation.details)

    def history(self, target_id: str, limit: int = 100) -> list[Observation]:
        with self._db() as db: rows = db.execute("SELECT * FROM observations WHERE target_id=? ORDER BY observed_at DESC LIMIT ?", (target_id, limit)).fetchall()
        return [Observation(r["id"], r["target_id"], r["observed_at"], r["session_id"], r["round_id"], tuple(Service(**x) for x in json.loads(r["services"])), r["fingerprint"], r["status"], json.loads(r["details"])) for r in rows]

    @staticmethod
    def _target(row):
        return Target(id=row["id"], name=row["name"], host=row["host"], role=Role(row["role"]), tags=tuple(json.loads(row["tags"])), notes=row["notes"])
