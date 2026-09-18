# Lab 05 — Mini A&D

Goal: combine enumeration, attack, defense, SLA, monitoring, evidence, and timing in a safe local simulation.

## Scenario

A deliberately vulnerable service is available only on localhost. It has a normal health/core flow and one documented learning vulnerability. The learner receives an own target and an enemy fixture target.

## Round loop

```text
baseline own health
  -> enumerate enemy fixture
  -> capture fixture flag
  -> patch own service
  -> rerun SLA
  -> replay exploit against own service
  -> inspect evidence
  -> rollback and verify recovery
```

## Rules

- No public or unknown target.
- No internet-wide scan.
- Use only declared fixture targets.
- Keep a timer and record hints.
- A flag alone is not a pass.

## Completion gate

- [ ] Own service stayed healthy.
- [ ] Enemy fixture was enumerated and attacked within scope.
- [ ] Flag result was validated and not committed.
- [ ] Patch closed the vulnerability.
- [ ] SLA remained green.
- [ ] Replay failed after patch.
- [ ] Rollback succeeded.
- [ ] Evidence is redacted.

Use this lab only after completing the individual labs. Add the actual fixture implementation in a future focused change; this README defines the learning contract first.