# Local Attack/Defense Scripts — Architecture Proposal

Status: proposal only; not deployed.

## Goal

Build a testable Python orchestration library for attack/defense training against localhost fixtures and mocks. Keep platform integration outside the first implementation.

## Non-goals and hard gates

- No GZCTF deployment.
- No external-target solver execution.
- No Internet/LAN scanning.
- No guessed GZCTF API fields or authentication.
- No real flag submission; use a local sink with explicit `submitted_to_platform: false`.
- No challenge-specific payload in the generic runner.

## Proposed layout

```text
attNdef/
├── pyproject.toml
├── Makefile
├── config/targets.json
├── docs/
│   ├── ai-consultation.md
│   ├── architecture-proposal.md
│   ├── evidence.md
│   └── interfaces.md
├── src/attnndef/
│   ├── core/models.py       # Target, Evidence, results, patch plan
│   ├── core/registry.py     # static local registry
│   ├── io/sink.py           # JSONL local/mock sink
│   ├── io/logging_setup.py  # structured operational logs
│   ├── attack/extractor.py  # raw output -> candidate flags
│   ├── attack/validator.py  # format, dedup, policy validation
│   ├── attack/runner.py     # bounded concurrency and timeout
│   ├── defense/health.py    # injected fixture health checks
│   ├── defense/patcher.py   # dry-run/apply/rollback strategies
│   ├── defense/replay.py    # exploit replay and regression orchestration
│   └── cli.py               # thin composable commands
├── tests/
│   ├── fixtures/mock_service.py
│   ├── test_registry.py
│   ├── test_extract_validate.py
│   ├── test_runner.py
│   ├── test_patch_rollback.py
│   └── test_replay_regression.py
└── artifacts/               # generated local evidence, gitignored
```

## Interfaces

- `TargetProvider`: local fixture provider now; future adapters later.
- `TargetRegistry`: resolves named targets from a local file and rejects non-local addresses in the first phase.
- `AttackFn(Target) -> RawAttackOutput`: injected challenge-specific function.
- `Extractor.extract(raw) -> list[str]`.
- `Validator.validate(flags) -> list[ValidatedFlag]`.
- `FlagSink.write(evidence)`: local-only sink in this phase.
- `HealthChecker.check(target) -> HealthResult`.
- `PatchStrategy.dry_run/apply/rollback(plan)`.
- `ReplayRunner.replay(target, attack_fn)`.
- `RegressionSuite.run(target) -> RegressionResult`.

All records should include a stable operation ID, target ID, timestamp, status, and error/evidence fields. Raw output must be retained separately from normalized flags. Secrets and real flags must not be written to ordinary logs.

## Attack flow

`discover` loads the local registry only.

`health` checks fixture availability.

`solve` runs the injected attack function with bounded concurrency, per-target timeout, and isolated failures.

`extract` parses raw results.

`submit` writes to the local sink only and records `submitted_to_platform: false`.

Every command supports a dry-run/explain mode where it does not mutate state.

## Defense flow

1. Snapshot relevant fixture state.
2. Run health check.
3. Replay the known local exploit and capture evidence.
4. Select a deterministic patch strategy; fail closed if none applies.
5. Dry-run and show the planned change.
6. Apply idempotently with a timestamped backup.
7. Re-run health check.
8. Replay the exploit.
9. Run legitimate regression tests.
10. Accept only if the exploit is blocked, health is good, and regressions pass; otherwise rollback and record why.

`rollback` must be explicit and independently testable.

## Implementation order

1. Add package metadata and test tooling.
2. Implement typed core records and local-address policy.
3. Implement registry loading and fixture records.
4. Implement JSONL sink and redacted structured logging.
5. Implement extractor and validator unit tests.
6. Implement runner with concurrency, timeout, and failure isolation.
7. Add mock service and a localhost-only attack fixture.
8. Implement health checks and replay.
9. Implement patch strategy with dry-run/apply/rollback tests.
10. Add CLI commands as thin adapters.
11. Run the complete local test suite and document evidence.

## Verification gates

Before any future platform adapter is considered:

- all tests pass without network access;
- tests prove non-local targets are rejected by the first-phase registry;
- attack and defense paths run only against mock/fixture targets;
- rollback restores the exact pre-patch state;
- accepted patches block replay while preserving health and regression behavior;
- local sink proves no external submit call exists;
- unknown GZCTF details remain explicitly documented, not inferred.

## Evidence status

- VERIFIED: package boundaries and workflow synthesis are based on the actual ChatGPT and Claude responses recorded in `docs/ai-consultation.md`.
- INFERRED: this directory structure is an appropriate implementation of that synthesis.
- UNKNOWN: GZCTF runtime API, authentication, endpoint paths, target discovery response shape, and submission protocol.
