# Learning Lab Standard

Every lab is local-only and intentionally vulnerable. Do not point a lab solver at an unrelated host.

## Required structure

```text
labs/<id-topic>/
  README.md
  notes-template.md
  vulnerable/
  patched/
  attack.py
  defense.md
  tests/
```

## Required README sections

1. Objective and prerequisites.
2. Scope and startup/cleanup commands.
3. Normal service/SLA contract.
4. Enumeration tasks.
5. Vulnerability hint levels 0–5.
6. Attack acceptance criteria.
7. Defense acceptance criteria.
8. Evidence and expected outputs.
9. Reset instructions.
10. References.

## Five-step progression

- Level 1: recognize the dangerous pattern from source.
- Level 2: reproduce it with source and hints.
- Level 3: exploit the service without source.
- Level 4: patch the root cause and preserve normal behavior.
- Level 5: complete a timed A&D variant: enumerate, capture, patch, monitor, and regress.

## Completion gate

A lab is not complete when a flag is captured. It is complete only when:

```text
attack proof
+ root-cause explanation
+ minimal patch
+ normal-flow/SLA pass
+ exploit replay failure
+ rollback proof
+ redacted evidence
```

## No-AI mode

No-AI mode may provide target startup, reset, health status, logs, and a timer. It must not provide source explanation, exploit payload, hints, or solution unless the learner explicitly exits no-AI mode.
