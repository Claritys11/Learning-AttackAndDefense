from __future__ import annotations
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from .tool_runner import ToolResult, ToolRunner
from ..targets import Scope, Service, Target

_PORT_SPEC = re.compile(r"^(?:\d{1,5}(?:-\d{1,5})?)(?:,(?:\d{1,5}(?:-\d{1,5})?))*$")

def validate_ports(value: str) -> str:
    if not _PORT_SPEC.fullmatch(value):
        raise ValueError("ports must be a comma-separated list of ports or ranges")
    for part in value.split(","):
        bounds = [int(x) for x in part.split("-")]
        if any(port < 1 or port > 65535 for port in bounds) or len(bounds) == 2 and bounds[0] > bounds[1]:
            raise ValueError("ports must use values from 1 to 65535 and valid ranges")
    return value

@dataclass(frozen=True)
class NmapAdapter:
    runner: ToolRunner
    binary: str = "nmap"

    def scan_target(self, target: Target, scope: Scope, *, ports: str = "1-1024", timeout_s: float = 30.0) -> tuple[ToolResult, tuple[Service, ...]]:
        scope.require(target)
        validate_ports(ports)
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
