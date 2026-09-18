"""Health checks: is a (fixture) service still up/responding after a
patch was applied? Pluggable check_fn so this stays fixture-agnostic.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Optional

from ..core.models import HealthResult, Target
from ..io.sink import LocalSink

CheckFn = Callable[[Target], bool]  # True == healthy; may raise on failure


@dataclass
class HealthChecker:
    check_fn: CheckFn
    timeout_s: float = 5.0
    sink: Optional[LocalSink] = None

    def check(self, target: Target) -> HealthResult:
        start = time.monotonic()
        try:
            ok = self._with_timeout(target)
            latency_ms = (time.monotonic() - start) * 1000
            result = HealthResult(target_id=target.id, ok=ok, latency_ms=latency_ms)
        except Exception as exc:  # noqa: BLE001
            latency_ms = (time.monotonic() - start) * 1000
            result = HealthResult(
                target_id=target.id, ok=False, latency_ms=latency_ms, details=repr(exc)
            )
        if self.sink:
            from ..core.models import Evidence

            self.sink.write(
                Evidence(
                    id=f"health-{target.id}-{int(start)}",
                    ts=start,
                    kind="health",
                    target_id=target.id,
                    ok=result.ok,
                    payload={"latency_ms": result.latency_ms, "details": result.details},
                )
            )
        return result

    def _with_timeout(self, target: Target) -> bool:
        # Simple thread-based timeout wrapper; check_fn is expected to be
        # a cheap local call (e.g. TCP connect) given the localhost scope.
        import concurrent.futures as cf

        with cf.ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(self.check_fn, target)
            return bool(fut.result(timeout=self.timeout_s))
