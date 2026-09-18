from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Protocol
from .models import Target
from .scope import Scope

class OperationKind(str, Enum):
    INTELLIGENCE = "intelligence"
    ATTACK = "attack"

class ScopeGuard(Protocol):
    def authorize(self, target: Target, operation: OperationKind) -> None: ...

@dataclass(frozen=True)
class ExecutionBoundary:
    scope: Scope

    def authorize(self, target: Target, operation: OperationKind) -> None:
        self.scope.require(target)
        if operation is OperationKind.ATTACK and target.role.value != "enemy":
            raise ValueError("attack operation requires an ENEMY target")

    def authorize_intelligence(self, target: Target) -> None:
        self.authorize(target, OperationKind.INTELLIGENCE)

    def authorize_attack(self, target: Target) -> None:
        self.authorize(target, OperationKind.ATTACK)
