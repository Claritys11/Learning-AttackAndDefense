# Phase 3F — Intelligence Diff

`attnndef.targets.diff` compares two immutable `Observation` objects without inferring vulnerabilities.

Stable service identity is `(protocol, port)`. The diff reports:

- `ADDED`: service exists only in the current observation;
- `REMOVED`: service exists only in the previous observation;
- `CHANGED`: name, version, or another service field changed;
- `STATUS_CHANGED`: only service status changed.

`IntelligenceDiff.entries` is structured for automation and `render()` provides compact operator-readable output. Entries use deterministic identity ordering. `diff_history()` compares the newest two observations when history is ordered newest-first by `TargetService.history()`.

Example:

```text
ADDED:
  443/tcp https
REMOVED:
  80/tcp http
CHANGED:
  22/tcp ssh
```

The engine reports observable changes only. It does not infer exploitability, vulnerability, ownership, or authorization.
