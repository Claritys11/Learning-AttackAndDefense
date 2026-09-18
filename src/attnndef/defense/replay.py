"""Exploit replay: after applying a patch, re-run the same attack against
the (now patched) local fixture and confirm:

  1. the exploit no longer succeeds (vulnerability closed), and
  2. the service is still healthy (patch didn't break functionality).

This composes AttackRunner + HealthChecker rather than reimplementing
either -- it's a regression gate, not a new execution mechanism.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from ..attack.runner import AttackRunner
from ..core.models import Evidence, Target
from ..defense.health import HealthChecker
from ..io.sink import LocalSink


@dataclass
class ReplayVerdict:
    target_id: str
    exploit_still_works: bool
    healthy: bool

    @property
    def patch_confirmed(self) -> bool:
        """Patch is good iff the exploit no longer works AND the
        service is still healthy."""
        return (not self.exploit_still_works) and self.healthy


class ExploitReplay:
    def __init__(
        self,
        runner: AttackRunner,
        health_checker: HealthChecker,
        sink: LocalSink | None = None,
    ) -> None:
        self.runner = runner
        self.health_checker = health_checker
        self.sink = sink

    def verify(self, target: Target) -> ReplayVerdict:
        [attack_result] = self.runner.run([target])
        health_result = self.health_checker.check(target)
        verdict = ReplayVerdict(
            target_id=target.id,
            exploit_still_works=attack_result.success,
            healthy=health_result.ok,
        )
        if self.sink:
            self.sink.write(
                Evidence(
                    id=f"replay-{target.id}-{int(time.time())}",
                    ts=time.time(),
                    kind="replay",
                    target_id=target.id,
                    ok=verdict.patch_confirmed,
                    payload={
                        "exploit_still_works": verdict.exploit_still_works,
                        "healthy": verdict.healthy,
                    },
                )
            )
        return verdict
