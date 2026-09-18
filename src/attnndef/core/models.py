from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

class Role(StrEnum):
    OWN = "own"
    ENEMY = "enemy"

@dataclass(frozen=True)
class Target:
    id: str
    host: str
    port: int
    role: Role = Role.OWN
    metadata: dict[str, Any] = field(default_factory=dict)

    def assert_local(self) -> None:
        if self.host not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError(f"non-local target rejected: {self.host}")

@dataclass
class Evidence:
    operation_id: str
    target_id: str
    status: str
    data: dict[str, Any] = field(default_factory=dict)

@dataclass
class HealthResult:
    healthy: bool
    detail: str = ""

@dataclass
class PatchPlan:
    strategy_id: str
    target_id: str
    files: list[str] = field(default_factory=list)
    explanation: str = ""
