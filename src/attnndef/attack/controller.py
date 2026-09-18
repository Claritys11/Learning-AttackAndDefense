"""Registry-driven multi-solver controller.

It loads only named, operator-approved dotted functions. It never discovers
endpoints, scans networks, or submits unless explicitly configured.
"""
from __future__ import annotations
import importlib
from dataclasses import dataclass
from typing import Callable
from .runner import AttackRunner
from .extractor import RegexExtractor
from ..core.models import Target, ExploitResult
from .submitter import SubmitResult

@dataclass(frozen=True)
class SolverSpec:
    name: str
    attack_fn: str
    tags: tuple[str, ...] = ()
    max_workers: int = 4
    timeout_s: float = 8.0

def load_callable(path: str) -> Callable:
    module, sep, attr = path.partition(":")
    if not sep: raise ValueError(f"expected module:function, got {path!r}")
    return getattr(importlib.import_module(module), attr)

class WaveController:
    def __init__(self, specs: list[SolverSpec], sink=None): self.specs, self.sink = specs, sink
    def run(self, targets: list[Target]) -> tuple[list[ExploitResult], list[str]]:
        results, flags = [], []
        for spec in self.specs:
            runner = AttackRunner(load_callable(spec.attack_fn), RegexExtractor(), self.sink, max_workers=spec.max_workers, per_target_timeout_s=spec.timeout_s)
            batch = runner.run([t for t in targets if not spec.tags or set(spec.tags) & set(t.tags)])
            results.extend(batch)
            flags.extend(r.flag for r in batch if r.success and r.flag)
        return results, flags
