"""Attack runner: fan-out an attack_fn over targets with bounded
concurrency and a per-target timeout, then extract/validate/record.

The actual exploit logic is NOT part of this design -- `attack_fn` is
supplied by the caller per-challenge. This module only orchestrates:
run -> collect raw output -> extract flag -> validate -> write evidence.
"""
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout
from typing import Callable, Iterable, Optional

from ..core.errors import TargetTimeoutError
from ..core.models import ExploitResult, Target
from ..io.sink import LocalSink
from .extractor import Extractor, FlagValidator

AttackFn = Callable[[Target], str]  # returns raw output; raises on hard failure

log = logging.getLogger("attnndef.attack.runner")


class AttackRunner:
    def __init__(
        self,
        attack_fn: AttackFn,
        extractor: Extractor,
        sink: Optional[LocalSink] = None,
        validator: Optional[FlagValidator] = None,
        max_workers: int = 4,
        per_target_timeout_s: float = 10.0,
    ) -> None:
        self.attack_fn = attack_fn
        self.extractor = extractor
        self.sink = sink
        self.validator = validator or FlagValidator()
        self.max_workers = max_workers
        self.per_target_timeout_s = per_target_timeout_s

    def _run_one(self, target: Target) -> ExploitResult:
        start = time.monotonic()
        try:
            raw = self.attack_fn(target)
            flag = self.extractor.extract(raw)
            ok = flag is not None and self.validator.accept(flag)
            return ExploitResult(
                target_id=target.id,
                success=ok,
                raw_output=raw,
                flag=flag if ok else None,
                duration_s=time.monotonic() - start,
            )
        except Exception as exc:  # noqa: BLE001 - boundary: convert to result
            return ExploitResult(
                target_id=target.id,
                success=False,
                error=repr(exc),
                duration_s=time.monotonic() - start,
            )

    def run(self, targets: Iterable[Target]) -> list[ExploitResult]:
        """Fan out over targets. `max_workers` bounds in-flight tasks
        (ThreadPoolExecutor's own queue semantics); each task gets an
        independent `per_target_timeout_s` budget.

        ASSUMPTION (UNKNOWN, see README): a timed-out task's thread is not
        forcibly killed (Python has no safe thread-kill primitive) -- we
        stop *waiting* on it and record a timeout result, but attack_fn
        should itself respect timeouts/cancellation where possible (e.g.
        socket timeouts) to avoid leaking threads.
        """
        targets = list(targets)
        results: list[ExploitResult] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_to_target = {pool.submit(self._run_one, t): t for t in targets}
            for fut, t in future_to_target.items():
                try:
                    res = fut.result(timeout=self.per_target_timeout_s)
                except FutTimeout:
                    res = ExploitResult(target_id=t.id, success=False, error="timeout")
                except Exception as exc:  # noqa: BLE001
                    res = ExploitResult(target_id=t.id, success=False, error=repr(exc))
                results.append(res)
        if self.sink:
            for r in results:
                self.sink.write(r.to_evidence(kind="attack"))
        return results
