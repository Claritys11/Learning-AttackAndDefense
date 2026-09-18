from __future__ import annotations
from dataclasses import dataclass
from .tool_runner import ToolResult, ToolRunner
from ..targets import Scope, Service, Target
from ..tools.nmap import parse_nmap_xml, validate_ports

__all__ = ["validate_ports", "parse_nmap_xml", "NmapAdapter"]

@dataclass(frozen=True)
class NmapAdapter:
    runner: ToolRunner
    binary: str = "nmap"

    def scan_target(self, target: Target, scope: Scope, *, ports: str = "1-1024", timeout_s: float = 30.0) -> tuple[ToolResult, tuple[Service, ...]]:
        scope.require(target)
        validate_ports(ports)
        result = self.runner.run([self.binary, "-oX", "-", "-p", ports, target.host], timeout_s=timeout_s)
        return result, parse_nmap_xml(result.stdout)
