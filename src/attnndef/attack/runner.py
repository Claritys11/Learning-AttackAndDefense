from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable
from attnndef.core.models import Target

class AttackRunner:
    def __init__(self, max_workers: int = 4, timeout: float = 10): self.max_workers, self.timeout = max_workers, timeout
    def run(self, targets: list[Target], attack_fn: Callable[[Target], str]) -> dict[str, str | Exception]:
        for t in targets: t.assert_local()
        results = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(attack_fn, t): t.id for t in targets}
            for future in as_completed(futures):
                tid = futures[future]
                try: results[tid] = future.result(timeout=self.timeout)
                except Exception as exc: results[tid] = exc
        return results
