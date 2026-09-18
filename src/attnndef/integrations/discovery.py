from __future__ import annotations
from dataclasses import dataclass
import ipaddress
import time
from ..targets import Scope, Target, TargetService, Role
from .tool_runner import ToolResult, ToolRunner

@dataclass(frozen=True)
class DiscoveredHost:
    host: str
    status: str
    observed_at: float

@dataclass(frozen=True)
class DiscoveryAdapter:
    runner: ToolRunner
    binary: str = "nmap"

    def discover(self, network: str, scope: Scope, *, timeout_s: float = 30.0) -> tuple[ToolResult, tuple[DiscoveredHost, ...]]:
        network_obj = ipaddress.ip_network(network, strict=False)
        allowed = [ipaddress.ip_network(x, strict=False) for x in scope.allowed_networks]
        if allowed and not any(network_obj.subnet_of(item) for item in allowed):
            raise ValueError("discovery network is outside configured scope")
        result = self.runner.run([self.binary, "-sn", "-oX", "-", str(network_obj)], timeout_s=timeout_s)
        return result, parse_discovery_xml(result.stdout)

def parse_discovery_xml(raw: str) -> tuple[DiscoveredHost, ...]:
    import xml.etree.ElementTree as ET
    if not raw.strip(): return ()
    try: root = ET.fromstring(raw)
    except ET.ParseError as exc: raise ValueError(f"invalid discovery XML: {exc}") from exc
    now = time.time(); hosts = []
    for host in root.findall(".//host"):
        address = host.find("address")
        status = host.find("status")
        if address is not None and address.attrib.get("addr"):
            hosts.append(DiscoveredHost(address.attrib["addr"], status.attrib.get("state", "unknown") if status is not None else "unknown", now))
    return tuple(hosts)

@dataclass
class DiscoveryService:
    targets: TargetService
    adapter: DiscoveryAdapter

    def discover(self, network: str, scope: Scope) -> tuple[DiscoveredHost, ...]:
        _, hosts = self.adapter.discover(network, scope)
        for host in hosts:
            target_id = f"discovered-{host.host}"
            if self.targets.get_target(target_id) is None:
                self.targets.add_target(Target(target_id, host.host, host.host, Role.UNKNOWN, ("discovered",)))
        return hosts
