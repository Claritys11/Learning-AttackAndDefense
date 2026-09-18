"""Explicit, opt-in submission adapter.

No endpoint is guessed: the operator supplies an exact URL and bearer token via
an environment variable. Dry-run is the default; live submission requires
``--live-submit`` in the controller.
"""
from __future__ import annotations
import os
from dataclasses import dataclass
from typing import Iterable
from urllib import request
import json

@dataclass(frozen=True)
class SubmitResult:
    flag: str
    accepted: bool
    status: int | None = None
    detail: str = ""

class HttpSubmitter:
    def __init__(self, endpoint: str, token_env: str = "ATTNDEF_SUBMIT_TOKEN", timeout: float = 8.0, live: bool = False):
        self.endpoint, self.token_env, self.timeout, self.live = endpoint, token_env, timeout, live
        if not endpoint.startswith("https://") and not endpoint.startswith("http://127.0.0.1") and not endpoint.startswith("http://localhost"):
            raise ValueError("submission endpoint must be HTTPS or localhost")

    def submit(self, flags: Iterable[str]) -> list[SubmitResult]:
        values = list(dict.fromkeys(flags))
        if not self.live:
            return [SubmitResult(f, False, detail="DRY-RUN: not submitted") for f in values]
        token = os.environ.get(self.token_env)
        if not token:
            raise RuntimeError(f"missing submission token env: {self.token_env}")
        body = json.dumps({"flags": values}).encode()
        req = request.Request(self.endpoint, data=body, method="POST", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        try:
            with request.urlopen(req, timeout=self.timeout) as resp:
                ok = 200 <= resp.status < 300
                return [SubmitResult(f, ok, resp.status, "accepted" if ok else "rejected") for f in values]
        except Exception as exc:
            return [SubmitResult(f, False, detail=f"submit error: {type(exc).__name__}") for f in values]
