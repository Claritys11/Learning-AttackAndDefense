from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import json
import sqlite3
import time
import uuid

@dataclass
class OperatorContext:
    profile: str = "Learning Lab"
    operator_name: str = ""
    team_name: str = ""
    team_id: str = ""
    vpn_interface: str = ""
    own_ip: str = ""
    team_subnet: str = ""
    enemy_subnet: str = ""
    platform: str = ""
    competition_name: str = ""
    flag_format: str = ""
    round_duration: int = 180
    credential_ref: str = ""
    selected_target: str = ""
    selected_service: str = ""
    current_round: int = 0
    session_id: str = ""

class ContextStore:
    def __init__(self, path: str | Path = "~/.attnndef/state.db"):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self):
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def _init(self):
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS context (id INTEGER PRIMARY KEY CHECK (id=1), payload TEXT NOT NULL, updated REAL NOT NULL)")

    def load(self) -> OperatorContext | None:
        with self._connect() as db:
            row = db.execute("SELECT payload FROM context WHERE id=1").fetchone()
        if not row:
            return None
        return OperatorContext(**json.loads(row["payload"]))

    def save(self, context: OperatorContext) -> OperatorContext:
        if not context.session_id:
            context.session_id = str(uuid.uuid4())
        payload = json.dumps(asdict(context), sort_keys=True)
        with self._connect() as db:
            db.execute("INSERT INTO context(id,payload,updated) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, updated=excluded.updated", (payload, time.time()))
        return context

    def clear(self):
        with self._connect() as db:
            db.execute("DELETE FROM context WHERE id=1")
