# Tools Guide

## Command map

| Command | Purpose | Network action |
|---|---|---|
| `discover` | Read the local target registry | None |
| `solve` | Run one solver over selected targets | Solver-defined, authorized targets only |
| `wave` | Run multiple solvers and collect flags | Solver-defined; submission dry-run by default |
| `extract` | Extract flags from saved output | None |
| `submit` | Record a local submission intent | None; always local-only |
| `patch` | Preview/apply a defense patch | Local file change only |
| `health` | Run a challenge-specific health/SLA check | Checker-defined, authorized targets only |
| `replay` | Verify exploit closure plus health | Checker/solver-defined |
| `rollback` | Restore a patch backup | Local file change only |

## Recommended order

```text
1. discover
2. health own
3. patch dry-run
4. patch apply
5. health own
6. replay own
7. refresh authorized enemy registry
8. solve/wave enemy
9. extract + validate + deduplicate
10. submit through a separately verified adapter
11. save evidence and round report
```

## Function contracts

### Attack function

```python
def attack_fn(target: Target) -> str:
    """Return raw output; raise on hard failure."""
```

The function must use its own network timeout, avoid unbounded retries, and never submit flags. The runner handles concurrency, extraction, validation, and evidence.

### Health function

```python
def check_fn(target: Target) -> tuple[bool, str]:
    """Return whether normal service behavior is healthy and why."""
```

A health function should test the legitimate checker contract, not the exploit path.

### Solver wave

```bash
wave --solver name=module:function [--solver name=module:function]
```

Solver names are labels for output and evidence. The module/function path is loaded explicitly; there is no automatic plugin discovery.

## Operational defaults

- `solve`: max 4 workers, 10-second per-target wait.
- `wave`: max 4 workers, 8-second per-target wait.
- Submission: dry-run.
- Target source: local registry.
- Real registry/evidence: ignored by Git.

Tune concurrency downward first if services are fragile or rate-limited.

## Writing effective solvers

A good solver is:

- challenge-specific;
- deterministic;
- bounded;
- low-noise;
- explicit about prerequisites;
- strict about flag format;
- independent from platform auth/submission;
- easy to replay against a fixture.

Suggested internal stages:

```text
preflight -> minimal request sequence -> exploit primitive
-> flag extraction -> format validation -> return raw evidence
```

## Writing effective defense checks

A good defense strategy:

- identifies the root cause;
- changes the smallest necessary behavior;
- preserves normal functionality;
- is idempotent;
- has a backup and rollback;
- emits evidence;
- has an exploit replay test;
- has an SLA regression test.

## Safety gate for live competition

Before `--live-submit`, confirm all of the following:

- The event explicitly authorizes automated submission.
- The endpoint belongs to the official event.
- The JSON schema and auth method are verified.
- The target registry contains only current authorized opponent instances.
- The flag format is confirmed.
- Rate limits and submission limits are understood.
- The token is loaded out-of-band.
- A dry-run output was reviewed.

If any item is unknown, remain in dry-run mode.
