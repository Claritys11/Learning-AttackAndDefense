from __future__ import annotations
import os
from dataclasses import dataclass

from ..integrations.tool_runner import ToolResult, ToolRunner
from .models import SshExecutionResult

@dataclass(frozen=True)
class SshAdapter:
    runner: ToolRunner
    binary: str = "ssh"

    def execute_command(
        self,
        host: str,
        command: str,
        *,
        port: int = 22,
        username: str = "root",
        identity_file: str | None = None,
        timeout_s: float = 15.0,
        strict_host_key_checking: str = "accept-new",
    ) -> tuple[ToolResult, SshExecutionResult]:
        if not host.strip():
            raise ValueError("SSH host must not be empty")
        if not command.strip():
            raise ValueError("SSH command must not be empty")
        if port < 1 or port > 65535:
            raise ValueError(f"invalid SSH port: {port}")

        connect_timeout = max(1, min(10, int(timeout_s)))
        cmd = [
            self.binary,
            "-p", str(port),
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={connect_timeout}",
            "-o", f"StrictHostKeyChecking={strict_host_key_checking}",
        ]
        if identity_file:
            expanded = os.path.expanduser(identity_file)
            cmd.extend(["-i", expanded])

        destination = f"{username}@{host}" if username else host
        cmd.extend([destination, command])

        result = self.runner.run(cmd, timeout_s=timeout_s)
        ssh_res = SshExecutionResult(
            host=host,
            port=port,
            user=username,
            command=command,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_s=result.duration_s,
            timed_out=result.timed_out,
            success=result.success,
            error_kind=result.error_kind,
            error=result.error or (result.stderr if not result.success else None),
        )
        return result, ssh_res

@dataclass
class SshService:
    adapter: SshAdapter

    def run(
        self,
        host: str,
        command: str,
        *,
        port: int = 22,
        username: str = "root",
        identity_file: str | None = None,
        timeout_s: float = 15.0,
    ) -> SshExecutionResult:
        result, ssh_res = self.adapter.execute_command(
            host,
            command,
            port=port,
            username=username,
            identity_file=identity_file,
            timeout_s=timeout_s,
        )
        return ssh_res

    def check_service_status(
        self,
        host: str,
        service_name: str,
        *,
        port: int = 22,
        username: str = "root",
        identity_file: str | None = None,
        timeout_s: float = 15.0,
    ) -> SshExecutionResult:
        cmd = f"systemctl status {service_name} --no-pager"
        return self.run(host, cmd, port=port, username=username, identity_file=identity_file, timeout_s=timeout_s)

    def read_file(
        self,
        host: str,
        remote_path: str,
        *,
        port: int = 22,
        username: str = "root",
        identity_file: str | None = None,
        timeout_s: float = 15.0,
    ) -> SshExecutionResult:
        cmd = f"cat {remote_path}"
        return self.run(host, cmd, port=port, username=username, identity_file=identity_file, timeout_s=timeout_s)
