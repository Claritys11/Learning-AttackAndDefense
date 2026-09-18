from __future__ import annotations
import ipaddress
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Sequence

from ..integrations.tool_runner import ToolResult, ToolRunner
from ..targets.models import Service

_PORT_SPEC = re.compile(r"^(?:\d{1,5}(?:-\d{1,5})?)(?:,(?:\d{1,5}(?:-\d{1,5})?))*$")

def validate_ports(value: str) -> str:
    cleaned = value.strip()
    if not _PORT_SPEC.fullmatch(cleaned):
        raise ValueError("ports must be a comma-separated list of ports or ranges (e.g. 80,443 or 1-1024)")
    for part in cleaned.split(","):
        bounds = [int(x) for x in part.split("-")]
        if any(port < 1 or port > 65535 for port in bounds) or (len(bounds) == 2 and bounds[0] > bounds[1]):
            raise ValueError("ports must use values from 1 to 65535 and valid ranges")
    return cleaned

@dataclass(frozen=True)
class DiscoveredHost:
    host: str
    status: str
    observed_at: float

def parse_discovery_xml(raw: str) -> tuple[DiscoveredHost, ...]:
    if not raw.strip():
        return ()
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError(f"invalid discovery XML: {exc}") from exc
    now = time.time()
    hosts = []
    for host in root.findall(".//host"):
        address = host.find("address")
        status = host.find("status")
        if address is not None and address.attrib.get("addr"):
            hosts.append(
                DiscoveredHost(
                    address.attrib["addr"],
                    status.attrib.get("state", "unknown") if status is not None else "unknown",
                    now,
                )
            )
    return tuple(hosts)

def parse_nmap_xml(raw: str) -> tuple[Service, ...]:
    if not raw.strip():
        return ()
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError(f"invalid nmap XML: {exc}") from exc
    services = []
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        service = port.find("service")
        services.append(
            Service(
                int(port.attrib["portid"]),
                port.attrib.get("protocol", "tcp"),
                service.attrib.get("name", "unknown") if service is not None else "unknown",
                service.attrib.get("product", "") if service is not None else "",
                "open",
            )
        )
    return tuple(services)

@dataclass(frozen=True)
class NmapAdapter:
    runner: ToolRunner
    binary: str = "nmap"

    def discover_hosts(self, network: str, *, timeout_s: float = 30.0) -> tuple[ToolResult, tuple[DiscoveredHost, ...]]:
        net_str = str(ipaddress.ip_network(network, strict=False))
        result = self.runner.run([self.binary, "-sn", "-oX", "-", net_str], timeout_s=timeout_s)
        return result, parse_discovery_xml(result.stdout)

    def scan_ports(self, host: str, *, ports: str = "1-1024", timeout_s: float = 30.0) -> tuple[ToolResult, tuple[Service, ...]]:
        valid_ports = validate_ports(ports)
        result = self.runner.run([self.binary, "-oX", "-", "-p", valid_ports, host], timeout_s=timeout_s)
        return result, parse_nmap_xml(result.stdout)

    def scan_services(self, host: str, *, ports: str = "1-1024", timeout_s: float = 60.0) -> tuple[ToolResult, tuple[Service, ...]]:
        valid_ports = validate_ports(ports)
        result = self.runner.run([self.binary, "-sV", "-sC", "-oX", "-", "-p", valid_ports, host], timeout_s=timeout_s)
        return result, parse_nmap_xml(result.stdout)

@dataclass
class NmapService:
    adapter: NmapAdapter

    def discover(self, network: str, *, timeout_s: float = 30.0) -> tuple[DiscoveredHost, ...]:
        result, hosts = self.adapter.discover_hosts(network, timeout_s=timeout_s)
        if not result.success:
            raise RuntimeError(f"Nmap host discovery failed: {result.stderr or result.error or 'unknown error'}")
        return hosts

    def scan_target(self, host: str, *, ports: str = "1-1024", service_detection: bool = False, timeout_s: float = 30.0) -> tuple[Service, ...]:
        if service_detection:
            result, services = self.adapter.scan_services(host, ports=ports, timeout_s=timeout_s)
        else:
            result, services = self.adapter.scan_ports(host, ports=ports, timeout_s=timeout_s)
        if not result.success:
            raise RuntimeError(f"Nmap port scan failed: {result.stderr or result.error or 'unknown error'}")
        return services
