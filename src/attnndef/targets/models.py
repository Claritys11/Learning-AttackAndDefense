from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class Role(str, Enum):
    OWN = "own"
    ENEMY = "enemy"
    NEUTRAL = "neutral"
    INFRASTRUCTURE = "infrastructure"
    UNKNOWN = "unknown"

@dataclass(frozen=True)
class Service:
    port: int
    protocol: str = "tcp"
    name: str = "unknown"
    version: str = ""
    status: str = "unknown"

@dataclass(frozen=True)
class Target:
    id: str
    name: str
    host: str
    role: Role = Role.UNKNOWN
    tags: tuple[str, ...] = ()
    notes: str = ""

@dataclass(frozen=True)
class Observation:
    id: int | None
    target_id: str
    observed_at: float
    session_id: str = ""
    round_id: int | None = None
    services: tuple[Service, ...] = ()
    fingerprint: str = ""
    status: str = "unknown"
    details: dict[str, Any] = field(default_factory=dict)
