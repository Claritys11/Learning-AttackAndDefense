from __future__ import annotations
from dataclasses import dataclass
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

    @property
    def duration_s(self) -> float:
        return self.finished_at - self.started_at

class ToolRunner:
    def run(self, command: Sequence[str], *, timeout_s: float = 10.0, cwd: str | None = None) -> ToolResult:
        args = tuple(str(x) for x in command)
        if not args or any("\x00" in x for x in args):
            raise ValueError("command must contain non-empty arguments without NUL bytes")
        started = time.time()
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=cwd, start_new_session=True)
        timed_out = False
        try:
            stdout, stderr = process.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            process.kill()
            stdout, stderr = process.communicate()
            stderr = (stderr or "") + "\nprocess terminated after timeout"
        finished = time.time()
        return ToolResult(args, process.returncode, stdout or "", stderr or "", started, finished, timed_out)
