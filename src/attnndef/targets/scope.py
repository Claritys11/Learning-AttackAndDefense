from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import ip_address, ip_network

from .models import Role, Target

class ScopeMode(str, Enum):
    LEARNING = "learning"
    LOCAL = "local"
    COMPETITION = "competition"

@dataclass(frozen=True)
class Scope:
    allowed_roles: frozenset[Role] = frozenset()
    allowed_networks: tuple[str, ...] = ()
    excluded_targets: frozenset[str] = frozenset()
    mode: ScopeMode = ScopeMode.LOCAL

    def validate(self, target: Target) -> tuple[bool, str]:
        if target.id in self.excluded_targets:
            return False, "target is explicitly excluded"
        if self.allowed_roles and target.role not in self.allowed_roles:
            return False, f"role {target.role.value} is outside scope"
        if self.allowed_networks:
            try:
                address = ip_address(target.host)
            except ValueError:
                return False, "target host is not an IP address"
            if not any(address in ip_network(network, strict=False) for network in self.allowed_networks):
                return False, "target network is outside scope"
        return True, "allowed"

    def require(self, target: Target) -> None:
        allowed, reason = self.validate(target)
        if not allowed:
            raise ValueError(f"target out of scope: {reason}")
