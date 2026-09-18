from abc import ABC, abstractmethod
from pathlib import Path
import shutil, time
class PatchStrategy(ABC):
    @abstractmethod
    def dry_run(self) -> str: ...
    @abstractmethod
    def apply(self) -> str: ...
    @abstractmethod
    def rollback(self) -> str: ...
class TextReplacePatch(PatchStrategy):
    def __init__(self, path: str, old: str, new: str): self.path, self.old, self.new, self.backup = Path(path), old, new, None
    def dry_run(self): return f"replace {self.old!r} -> {self.new!r} in {self.path}"
    def apply(self):
        text = self.path.read_text();
        if self.old not in text: raise ValueError("patch marker not found")
        self.backup = self.path.with_name(self.path.name + f".bak.{int(time.time())}"); shutil.copy2(self.path, self.backup)
        self.path.write_text(text.replace(self.old, self.new, 1)); return str(self.backup)
    def rollback(self):
        if not self.backup: raise RuntimeError("no backup available")
        shutil.copy2(self.backup, self.path); return str(self.path)
