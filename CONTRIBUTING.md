# Contributing to Learning A&D

This repository is for learning authorized Attack & Defense security engineering.

## Contribution rules

- Work only on local fixtures, owned labs, or explicitly authorized competition targets.
- Never commit credentials, tokens, private keys, real flags, private target lists, or sensitive logs.
- Keep intentionally vulnerable code isolated under a clearly named lab.
- Include both an attack test and a defensive regression test.
- Explain the root cause instead of adding only a payload.
- Keep examples reproducible with documented versions and cleanup steps.
- Mark platform-specific behavior as `VERIFIED`, `INFERRED`, or `UNKNOWN`.

## Learning module template

A useful module contains:

1. Objective and prerequisites.
2. Threat model and trust boundary.
3. Safe setup and teardown.
4. Normal behavior/SLA contract.
5. Enumeration observations.
6. Minimal exploit reproduction.
7. Root-cause analysis.
8. Minimal patch and trade-offs.
9. Regression, replay, and rollback tests.
10. References and limitations.

## Pull requests

Run:

```bash
.venv/bin/pytest -q
```

Describe what was tested and confirm that no external target was contacted. Do not include raw flags or secrets in screenshots, logs, or fixtures.
