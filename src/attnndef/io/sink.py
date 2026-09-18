import json
from pathlib import Path
from dataclasses import asdict
from attnndef.core.models import Evidence
class LocalSink:
    def __init__(self, path: str | Path): self.path = Path(path)
    def write(self, evidence: Evidence) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as f: f.write(json.dumps(asdict(evidence), sort_keys=True) + "\n")
