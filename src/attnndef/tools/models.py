from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping

from ..core.models import Evidence

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
    success: bool = True
    error_kind: str | None = None
    error: str | None = None
    returncode: int | None = 0

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
    success: bool = True
    error_kind: str | None = None
    error: str | None = None
    returncode: int | None = 0

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
    success: bool = False
    error_kind: str | None = None
    error: str | None = None

@dataclass(frozen=True)
class PacketCaptureResult:
    interface: str
    packet_count: int
    filter_bpf: str
    raw_output: str
    duration_s: float
    pcap_path: str | None = None
    success: bool = True
    error_kind: str | None = None
    error: str | None = None
    returncode: int | None = 0

@dataclass(frozen=True)
class GdbResult:
    binary_path: str
    commands: tuple[str, ...]
    stdout: str
    stderr: str
    returncode: int | None
    duration_s: float
    success: bool = True
    error_kind: str | None = None
    error: str | None = None

@dataclass(frozen=True)
class SystemToolResult:
    tool: str
    subcommand: str
    stdout: str
    stderr: str
    returncode: int | None
    duration_s: float
    parsed: Any = None
    success: bool = True
    error_kind: str | None = None
    error: str | None = None

@dataclass(frozen=True)
class ToolExecutionRecord:
    """Structured, reproducible record of an operator tool execution."""
    tool: str
    operation: str
    target: str
    timestamp: float
    duration_s: float
    parameters: dict[str, Any]
    success: bool
    id: str = field(default_factory=lambda: f"exec-{uuid.uuid4().hex[:8]}")
    returncode: int | None = None
    error_kind: str | None = None
    error: str | None = None
    output_summary: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_evidence(self) -> Evidence:
        return Evidence(
            id=f"{self.tool}-{uuid.uuid4().hex[:8]}",
            ts=self.timestamp,
            kind=f"tool_{self.tool}",
            target_id=self.target or "global",
            ok=self.success,
            payload={
                "tool_execution_id": self.id,
                "operation": self.operation,
                "parameters": self.parameters,
                "duration_s": self.duration_s,
                "returncode": self.returncode,
                "error_kind": self.error_kind,
                "error": self.error,
                "summary": self.output_summary,
                "details": self.details,
            },
        )
