"""Defense patch strategy: dry-run (preview only) -> apply (backup +
mutate) -> rollback (restore backup).

Scope: acts on local fixture files representing a service's config
(e.g. a template/config the mock service reads). No process restart /
orchestration platform hookup is implemented (UNKNOWN, see README).
"""
from __future__ import annotations

import shutil
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from ..core.errors import PatchError, RollbackError
from ..core.models import Evidence, PatchPlan, Target
from ..io.sink import LocalSink


class PatchStrategy(ABC):
    """One strategy = one kind of change (e.g. "replace a config value").
    Concrete strategies decide *what* changes; this class handles the
    common dry-run/apply/rollback lifecycle and backup bookkeeping.
    """

    def __init__(self, backup_dir: str | Path, sink: Optional[LocalSink] = None) -> None:
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.sink = sink

    @abstractmethod
    def _compute_new_content(self, current: str) -> str:
        """Return the patched file content given the current content."""

    @abstractmethod
    def description(self) -> str:
        ...

    def _target_path(self, target: Target) -> Path:
        try:
            return Path(target.metadata["config_path"])
        except KeyError as exc:
            raise PatchError(f"target {target.id} has no metadata.config_path") from exc

    def dry_run(self, target: Target) -> PatchPlan:
        path = self._target_path(target)
        current = path.read_text() if path.exists() else ""
        new = self._compute_new_content(current)
        plan = PatchPlan.new(target.id, self.description())
        plan.dry_run = True
        plan.diff_preview = self._simple_diff(current, new)
        self._record(plan, kind="patch_dry_run")
        return plan

    def apply(self, target: Target) -> PatchPlan:
        path = self._target_path(target)
        current = path.read_text() if path.exists() else ""
        new = self._compute_new_content(current)

        backup_path = self.backup_dir / f"{target.id}-{int(time.time())}.bak"
        if path.exists():
            shutil.copy2(path, backup_path)
        else:
            backup_path.write_text("")  # empty-file sentinel = "did not exist"

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(new)

        plan = PatchPlan.new(target.id, self.description())
        plan.dry_run = False
        plan.applied = True
        plan.applied_at = time.time()
        plan.backup_path = str(backup_path)
        plan.diff_preview = self._simple_diff(current, new)
        self._record(plan, kind="patch_apply")
        return plan

    def rollback(self, plan: PatchPlan, target: Target) -> PatchPlan:
        if not plan.applied or not plan.backup_path:
            raise RollbackError(f"plan {plan.id} was never applied")
        backup = Path(plan.backup_path)
        if not backup.exists():
            raise RollbackError(f"backup missing: {backup}")
        path = self._target_path(target)
        if backup.stat().st_size == 0 and backup.read_text() == "":
            # sentinel for "file did not exist before apply"
            path.unlink(missing_ok=True)
        else:
            shutil.copy2(backup, path)
        plan.rolled_back = True
        self._record(plan, kind="patch_rollback")
        return plan

    @staticmethod
    def _simple_diff(old: str, new: str) -> str:
        if old == new:
            return "(no change)"
        return f"- {old!r}\n+ {new!r}"

    def _record(self, plan: PatchPlan, kind: str) -> None:
        if not self.sink:
            return
        self.sink.write(
            Evidence(
                id=plan.id,
                ts=time.time(),
                kind=kind,
                target_id=plan.target_id,
                ok=True,
                payload={
                    "description": plan.description,
                    "backup_path": plan.backup_path,
                    "diff_preview": plan.diff_preview,
                },
            )
        )


class TextReplacePatch(PatchStrategy):
    """Concrete example strategy: literal search/replace in a config file.
    Stand-in for whatever concrete remediation a challenge needs.
    """

    def __init__(self, backup_dir, search: str, replace: str, sink=None) -> None:
        super().__init__(backup_dir, sink)
        self.search = search
        self.replace = replace

    def _compute_new_content(self, current: str) -> str:
        return current.replace(self.search, self.replace)

    def description(self) -> str:
        return f"replace {self.search!r} -> {self.replace!r}"
