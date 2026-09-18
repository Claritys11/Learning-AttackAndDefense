from __future__ import annotations
import hashlib
import json
import time
from dataclasses import dataclass
from ..targets import Observation, Scope, Target, TargetService
from .nmap import NmapAdapter

@dataclass
class ReconService:
    targets: TargetService
    nmap: NmapAdapter

    def scan_target(self, target: Target, scope: Scope, *, session_id: str = "", round_id: int | None = None, ports: str = "1-1024") -> Observation:
        result, services = self.nmap.scan_target(target, scope, ports=ports)
        fingerprint = hashlib.sha256(json.dumps([s.__dict__ for s in services], sort_keys=True).encode()).hexdigest()[:16]
        observation = Observation(None, target.id, time.time(), session_id, round_id, services, fingerprint, "up" if result.returncode == 0 and not result.timed_out else "unknown", {"tool": "nmap", "returncode": result.returncode, "stderr": result.stderr, "duration_s": result.duration_s})
        return self.targets.record_observation(observation)
