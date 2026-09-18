from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Mapping

@dataclass(frozen=True)
class HttpRequest:
    url: str
    method: str = "GET"
    headers: Mapping[str, str] = field(default_factory=dict)
    body: str | None = None
    timeout_s: float = 10.0

@dataclass(frozen=True)
class HttpResponse:
    status_code: int
    headers: dict[str, str]
    body: str
    duration_s: float
    raw_output: str = ""

@dataclass(frozen=True)
class FfufMatch:
    url: str
    status: int
    length: int
    words: int
    lines: int
    redirect_location: str = ""

@dataclass(frozen=True)
class FfufScanResult:
    target_url: str
    wordlist: str
    matches: tuple[FfufMatch, ...]
    duration_s: float
    raw_output: str = ""

@dataclass(frozen=True)
class SshExecutionResult:
    host: str
    port: int
    user: str
    command: str
    returncode: int | None
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False

@dataclass(frozen=True)
class PacketCaptureResult:
    interface: str
    packet_count: int
    filter_bpf: str
    raw_output: str
    duration_s: float
    pcap_path: str | None = None

@dataclass(frozen=True)
class GdbResult:
    binary_path: str
    commands: tuple[str, ...]
    stdout: str
    stderr: str
    returncode: int | None
    duration_s: float

@dataclass(frozen=True)
class SystemToolResult:
    tool: str
    subcommand: str
    stdout: str
    stderr: str
    returncode: int | None
    duration_s: float
    parsed: Any = None
