# Phase 3F — Intelligence Diff

`attnndef.targets.diff` compares two immutable `Observation` objects without inferring vulnerabilities.

Stable service identity is `(protocol, port)`. The diff reports:

- `ADDED`: service exists only in the current observation;
- `REMOVED`: service exists only in the previous observation;
- `CHANGED`: name, version, or another service field changed;
- `STATUS_CHANGED`: only service status changed.

`IntelligenceDiff` carries observation IDs and session/round metadata at result level. `diff_history(history, newest_first=True)` makes ordering explicit; it compares newest-to-previous by default and oldest-to-newest when `newest_first=False`.

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
