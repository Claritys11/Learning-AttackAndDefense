from __future__ import annotations
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from .tool_runner import ToolResult, ToolRunner
from ..targets import Scope, Service, Target

@dataclass(frozen=True)
class NmapAdapter:
    runner: ToolRunner
    binary: str = "nmap"

    def scan_target(self, target: Target, scope: Scope, *, ports: str = "1-1024", timeout_s: float = 30.0) -> tuple[ToolResult, tuple[Service, ...]]:
        scope.require(target)
        result = self.runner.run([self.binary, "-oX", "-", "-p", ports, target.host], timeout_s=timeout_s)
        return result, parse_nmap_xml(result.stdout)

def parse_nmap_xml(raw: str) -> tuple[Service, ...]:
    if not raw.strip(): return ()
    try: root = ET.fromstring(raw)
    except ET.ParseError as exc: raise ValueError(f"invalid nmap XML: {exc}") from exc
    services = []
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is None or state.attrib.get("state") != "open": continue
        service = port.find("service")
        services.append(Service(int(port.attrib["portid"]), port.attrib.get("protocol", "tcp"), service.attrib.get("name", "unknown") if service is not None else "unknown", service.attrib.get("product", "") if service is not None else "", "open"))
    return tuple(services)
