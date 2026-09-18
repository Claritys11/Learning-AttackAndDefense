import json
from pathlib import Path
from .models import Target, Role

class TargetRegistry:
    def __init__(self, targets: list[Target]): self.targets = targets
    @classmethod
    def from_file(cls, path: str | Path) -> "TargetRegistry":
        raw = json.loads(Path(path).read_text())
        targets = [Target(id=x["id"], host=x["host"], port=int(x["port"]), role=Role(x.get("role", "own")), metadata=x.get("metadata", {})) for x in raw]
        for target in targets: target.assert_local()
        return cls(targets)
    def get(self, target_id: str) -> Target:
        return next(t for t in self.targets if t.id == target_id)
