from __future__ import annotations
from dataclasses import dataclass
import os
import signal
import subprocess
import time
from typing import Sequence

@dataclass(frozen=True)
class ToolResult:
    command: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    started_at: float
    finished_at: float
    timed_out: bool = False
    error_kind: str | None = None
    error: str | None = None

    @property
    def duration_s(self) -> float:
        return self.finished_at - self.started_at

    @property
    def duration(self) -> float:
        return self.duration_s

    @property
    def success(self) -> bool:
        return self.returncode == 0 and not self.timed_out and self.error_kind in (None, "success")

class ToolRunner:
    def run(
        self,
        command: Sequence[str],
        *,
        timeout_s: float = 10.0,
        cwd: str | None = None,
        input: str | None = None,
    ) -> ToolResult:
        args = tuple(str(x) for x in command)
        if not args or any(not x or "\x00" in x for x in args):
            raise ValueError("command must contain non-empty arguments without NUL bytes")
        started = time.time()
        try:
            process = subprocess.Popen(
                args,
                stdin=subprocess.PIPE if input is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd,
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            now = time.time()
            return ToolResult(args, None, "", str(exc), started, now, error_kind="not_found", error=str(exc))
        except PermissionError as exc:
            now = time.time()
            return ToolResult(args, None, "", str(exc), started, now, error_kind="permission", error=str(exc))
        except OSError as exc:
            now = time.time()
            return ToolResult(args, None, "", str(exc), started, now, error_kind="os_error", error=str(exc))
        timed_out = False
        try:
            stdout, stderr = process.communicate(input=input, timeout=timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
            stdout, stderr = process.communicate()
            stderr = (stderr or "") + "\nprocess group terminated after timeout"
        finished = time.time()
        if timed_out:
            error_kind = "timeout"
        elif process.returncode == 0:
            error_kind = "success"
        else:
            error_kind = "nonzero_exit"
        return ToolResult(
            args,
            process.returncode,
            stdout or "",
            stderr or "",
            started,
            finished,
            timed_out,
            error_kind=error_kind,
        )
