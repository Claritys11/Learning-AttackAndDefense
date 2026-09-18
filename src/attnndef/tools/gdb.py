from __future__ import annotations
import os
from dataclasses import dataclass
from typing import Sequence

from ..integrations.tool_runner import ToolResult, ToolRunner
from .models import GdbResult

@dataclass(frozen=True)
class GdbAdapter:
    runner: ToolRunner
    binary: str = "gdb"

    def execute_batch(
        self,
        binary_path: str,
        commands: Sequence[str],
        *,
        core_path: str | None = None,
        timeout_s: float = 15.0,
    ) -> tuple[ToolResult, GdbResult]:
        expanded_bin = os.path.expanduser(binary_path)
        if not os.path.exists(expanded_bin):
            raise FileNotFoundError(f"target binary not found: {binary_path}")

        cmd = [self.binary, "--batch", "-q"]
        for ex in commands:
            cmd.extend(["-ex", ex])

        if core_path:
            expanded_core = os.path.expanduser(core_path)
            cmd.extend(["-c", expanded_core])

        cmd.append(expanded_bin)

        result = self.runner.run(cmd, timeout_s=timeout_s)
        gdb_res = GdbResult(
            binary_path=binary_path,
            commands=tuple(commands),
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
            duration_s=result.duration_s,
            success=result.success,
            error_kind=result.error_kind,
            error=result.error or (result.stderr if not result.success else None),
        )
        return result, gdb_res

@dataclass
class GdbService:
    adapter: GdbAdapter

    def inspect_binary(self, binary_path: str, timeout_s: float = 10.0) -> GdbResult:
        commands = [
            "info files",
            "info functions",
            "disassemble main",
        ]
        _, res = self.adapter.execute_batch(binary_path, commands, timeout_s=timeout_s)
        return res

    def analyze_crash(
        self,
        binary_path: str,
        core_path: str | None = None,
        timeout_s: float = 15.0,
    ) -> GdbResult:
        commands = [
            "backtrace",
            "info registers",
            "x/16i $rip",
        ]
        _, res = self.adapter.execute_batch(binary_path, commands, core_path=core_path, timeout_s=timeout_s)
        return res

    def inspect_registers(
        self,
        binary_path: str,
        core_path: str | None = None,
        timeout_s: float = 10.0,
    ) -> GdbResult:
        commands = ["info registers"]
        _, res = self.adapter.execute_batch(binary_path, commands, core_path=core_path, timeout_s=timeout_s)
        return res

    def inspect_memory(
        self,
        binary_path: str,
        address_or_symbol: str = "main",
        core_path: str | None = None,
        timeout_s: float = 10.0,
    ) -> GdbResult:
        cleaned = address_or_symbol.strip()
        if not cleaned or not all(c.isalnum() or c in "_*+-$" for c in cleaned):
            raise ValueError("invalid address or symbol format")
        commands = [f"x/16gx {cleaned}"]
        _, res = self.adapter.execute_batch(binary_path, commands, core_path=core_path, timeout_s=timeout_s)
        return res
