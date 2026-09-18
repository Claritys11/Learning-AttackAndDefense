from __future__ import annotations
import shutil
from dataclasses import dataclass

from ..integrations.tool_runner import ToolResult, ToolRunner
from .models import SystemToolResult

@dataclass(frozen=True)
class SystemAdapter:
    runner: ToolRunner

    def run_tool(self, binary: str, args: list[str], *, timeout_s: float = 10.0) -> tuple[ToolResult, SystemToolResult]:
        cmd = [binary] + args
        result = self.runner.run(cmd, timeout_s=timeout_s)
        sys_res = SystemToolResult(
            tool=binary,
            subcommand=" ".join(args),
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
            duration_s=result.duration_s,
        )
        return result, sys_res

@dataclass
class SystemService:
    adapter: SystemAdapter

    def ss_listening(self) -> SystemToolResult:
        _, res = self.adapter.run_tool("ss", ["-tulpn"])
        return res

    def ss_all(self) -> SystemToolResult:
        _, res = self.adapter.run_tool("ss", ["-tan"])
        return res

    def ps_aux(self) -> SystemToolResult:
        _, res = self.adapter.run_tool("ps", ["aux"])
        return res

    def systemctl_status(self, service_name: str) -> SystemToolResult:
        if not service_name.strip():
            raise ValueError("service name must not be empty")
        _, res = self.adapter.run_tool("systemctl", ["status", service_name.strip(), "--no-pager"])
        return res

    def ip_addr(self) -> SystemToolResult:
        _, res = self.adapter.run_tool("ip", ["addr"])
        return res

    def ip_route(self) -> SystemToolResult:
        _, res = self.adapter.run_tool("ip", ["route"])
        return res

    def dig_lookup(self, domain: str, record_type: str = "A") -> SystemToolResult:
        if not domain.strip():
            raise ValueError("domain must not be empty")
        _, res = self.adapter.run_tool("dig", ["+short", domain.strip(), record_type])
        return res

    def wireguard_status(self, interface: str | None = None) -> SystemToolResult:
        args = ["show"]
        if interface:
            args.append(interface)
        _, res = self.adapter.run_tool("wg", args)
        return res
