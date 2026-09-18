# attnndef — local fixture Attack/Defense scaffolding

Scope: **localhost fixtures/mocks only**. No platform integration (e.g.
GZCTF) is implemented or assumed — every place that would need one is
marked UNKNOWN below and left as an explicit extension point instead of
guessed.

## Learning roadmap

The comprehensive LKS-aligned roadmap is in `docs/ad-learning-roadmap.md`. It maps the 2024/2025 topics to the GZCTF/TCP1P A&D round model, with weekly phases, lab deliverables, attack/defense gates, monitoring practice, and a final mock competition.


Read `docs/competition-runbook.md` before competition use. It explains the exact round cadence, defensive patch/regression lane, bounded offensive wave, evidence handling, reviewed platform-adapter boundary, GZCTF telemetry, and failure handling. The built-in `submit` command remains local-only by design.

Research synthesis and source captures are in `docs/gzctf-ad-workflow-analysis.md` and `docs/source-*.txt`.

## Layout

```
src/attnndef/
  core/     models.py (Target, ExploitResult, Evidence, PatchPlan, HealthResult),
            registry.py (TargetRegistry, loads config/targets.json), errors.py
  io/       sink.py (LocalSink: append-only JSONL evidence),
            logging_setup.py (structured JSON operational logs)
  attack/   extractor.py (RegexExtractor + FlagValidator),
            runner.py (AttackRunner: bounded concurrency + per-target timeout)
  defense/  health.py (HealthChecker), patcher.py (PatchStrategy: dry-run/
            apply/rollback, TextReplacePatch concrete example),
            replay.py (ExploitReplay: post-patch regression gate)
  `wave` — orchestrate multiple approved solvers, then optionally submit via an
              explicit HTTPS/localhost adapter (dry-run by default).
tests/      17 tests incl. a self-contained mock fixture service (tests/fixtures/mock_service.py)
config/     targets.example.json — copy to config/targets.json and edit
```

## Run tests

```
pip install pytest --break-system-packages   # or use a venv
python -m pytest -q
```

## CLI quick reference

```
attnndef discover --role enemy
attnndef solve --attack-fn mypkg.exploits.web01:attack_fn --role enemy
attnndef extract --input raw.txt --target-id svc-enemy-01
attnndef submit --target-id svc-enemy-01 --flag "FLAG{...}"     # local record only, see UNKNOWN
attnndef patch --target-id svc-own-01 --search DEBUG=true --replace DEBUG=false --mode dry-run
attnndef patch --target-id svc-own-01 --search DEBUG=true --replace DEBUG=false --mode apply
attnndef health --check-fn mypkg.checks:tcp_check --role own
attnndef replay --target-id svc-own-01 --attack-fn mypkg.exploits.web01:attack_fn --check-fn mypkg.checks:tcp_check
attnndef rollback --target-id svc-own-01 --backup-path backups/svc-own-01-....bak --config-path fixtures/own-web/service.ini
```

`--attack-fn` / `--check-fn` are dotted `module:function` imports you
provide per challenge — this scaffolding deliberately does not contain
any exploit logic.

## Implementation order (already built in this order; use it if extending)

1. `core/models.py`, `core/errors.py` — no dependencies, defines the shared vocabulary.
2. `core/registry.py` — depends only on models; easiest to unit test (pure JSON parsing).
3. `io/sink.py`, `io/logging_setup.py` — infra used by everything downstream.
4. `attack/extractor.py` — pure functions, no I/O, cheapest to get right first.
5. `attack/runner.py` — concurrency + timeout; test with fake `attack_fn`s before touching real sockets.
6. `defense/health.py` — same timeout pattern as the runner, smaller surface.
7. `defense/patcher.py` — file I/O with backup/rollback; test on tmp_path fixtures only.
8. `defense/replay.py` — composes runner + health, no new mechanism.
9. `cli.py` — wires everything; test manually against `config/targets.example.json` + the mock fixture.
10. `tests/fixtures/mock_service.py` + full test suite — validates the whole pipeline end-to-end locally.

Suggested next steps once you're ready to point this at a real environment:
11. Add a concrete `attack_fn`/`check_fn` per challenge in your own module (outside this package).
12. Only then design a platform adapter (submission, discovery) — see UNKNOWN below — as a *separate* module so it can be swapped/mocked in tests.

## UNKNOWN / explicitly not implemented (do not assume these)

- **Any GZCTF (or other platform) HTTP API** — team/service discovery, flag
  submission endpoint & schema, auth/session handling. `discover` only
  reads a local JSON file; `submit` only writes a local evidence record
  with `submitted_to_platform: false`. Wire a real client in separately
  once the actual API is confirmed from official docs.
- **Real network target discovery** — no port scanning / service
  enumeration is implemented; targets are declared by hand in
  `config/targets.json`.
- **Live-round polling loop** — the CLI is single-shot per invocation
  (`solve` runs once and exits). A continuous loop (e.g. run every N
  seconds during a round) is not implemented; wrap the CLI in a scheduler
  if needed.
- **Thread cancellation on timeout** — Python cannot forcibly kill a
  running thread. A timed-out `attack_fn`/`check_fn` call is *reported*
  as failed but its thread may keep running in the background until it
  finishes naturally. `attack_fn`/`check_fn` implementations should use
  their own socket/HTTP timeouts to bound this.
- **Concurrency/timeout defaults** (`max_workers=4`, `per_target_timeout_s=10s`,
  health `timeout_s=5s`) are placeholders, not tuned for any specific
  competition's network conditions.
- **Backup retention policy** — `PatchStrategy` writes one timestamped
  backup per `apply()` call and never deletes old ones; add pruning if
  disk usage matters.
- **Process/service restart after a patch** — `patcher.apply()` only
  rewrites the config file fixture; if a real service needs a restart to
  pick up changes, that hook is not implemented here.
- **What "healthy" means per challenge** — `HealthChecker` is fully
  pluggable (`check_fn`); no generic definition (TCP connect vs HTTP 200
  vs app-level check) is assumed beyond the example in
  `tests/fixtures/mock_service.py`.
- **Flag format** — `RegexExtractor` defaults to a generic `FLAG{...}`
  pattern; override `pattern=` for the actual competition's format.
- **Credentials/auth for targets** — no auth handling exists anywhere in
  this design; add it inside your own `attack_fn`/`check_fn`.
