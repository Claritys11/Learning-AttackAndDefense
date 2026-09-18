from __future__ import annotations

from ..integrations.tool_runner import ToolResult, ToolRunner
from .ffuf import FfufAdapter, FfufService, parse_ffuf_json
from .gdb import GdbAdapter, GdbService
from .http import HttpAdapter, HttpService, parse_http_raw
from .models import (
    FfufMatch,
    FfufScanResult,
    GdbResult,
    HttpRequest,
    HttpResponse,
    PacketCaptureResult,
    SshExecutionResult,
    SystemToolResult,
    ToolExecutionRecord,
)
from .nmap import DiscoveredHost, NmapAdapter, NmapService, parse_discovery_xml, parse_nmap_xml, validate_ports
from .ssh import SshAdapter, SshService
from .system import SystemAdapter, SystemService
from .tcpdump import TcpdumpAdapter, TcpdumpService

__all__ = [
    "ToolRunner",
    "ToolResult",
    "HttpRequest",
    "HttpResponse",
    "HttpAdapter",
    "HttpService",
    "parse_http_raw",
    "NmapAdapter",
    "NmapService",
    "DiscoveredHost",
    "validate_ports",
    "parse_nmap_xml",
    "parse_discovery_xml",
    "FfufAdapter",
    "FfufService",
    "FfufMatch",
    "FfufScanResult",
    "parse_ffuf_json",
    "SshAdapter",
    "SshService",
    "SshExecutionResult",
    "TcpdumpAdapter",
    "TcpdumpService",
    "PacketCaptureResult",
    "GdbAdapter",
    "GdbService",
    "GdbResult",
    "SystemAdapter",
    "SystemService",
    "SystemToolResult",
    "ToolExecutionRecord",
]
