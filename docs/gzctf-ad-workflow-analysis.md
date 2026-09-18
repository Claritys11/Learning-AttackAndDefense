# GZ::CTF A&D Workflow Analysis

Status: research and architecture only. No platform deployment and no external solver execution.

## Sources actually inspected

Primary documentation:

- https://dimasc.tf/GZCTF/guide/start/introduction
- https://dimasc.tf/GZCTF/guide/features/attack-defense
- https://dimasc.tf/GZCTF/guide/authoring/templates
- https://dimasc.tf/GZCTF/guide/features/scoring
- https://dimasc.tf/GZCTF/guide/features/live-feed
- https://dimasc.tf/GZCTF/guide/features/access
- https://dimasc.tf/GZCTF/guide/features/snapshots
- https://dimasc.tf/GZCTF/guide/features/honeypots
- https://dimasc.tf/GZCTF/guide/features/anti-cheat
- https://dimasc.tf/GZCTF/guide/authoring/challenge-yaml

Source extraction is preserved in `docs/source-*.txt`. The linked fork advertises itself as an A&D-specific fork; upstream behavior must not be assumed equivalent.

Repositories inspected:

- `refs/GZCTF`: GZCTF fork source checkout, including A&D controllers, migrations, UI, traffic, honeypot, snapshot, and anti-cheat code.
- `refs/TCP1PADTesting`: public challenge/event examples. No solver was executed.
- `refs/gzctf-platform-template`: repository clone for platform/config reference.
- `refs/Attack-Defense`: existing local reference checkout.

## Actual A&D mental model

A&D is not a single attacker script. It is a timed control loop around per-team service instances:

```text
challenge.yml + event manifest
        |
        v
import/build/review -> challenge definition
        |
        v
one service instance per team/challenge
        |
        +--> team access: WireGuard reaches private challenge network
        +--> SSH jump reaches own container for patching/inspection
        +--> attack client reaches opponent instances
        +--> checker periodically tests legitimate SLA behavior
        +--> scoring awards attack captures and defense/service health
        +--> live feed emits round/submission/health events
        +--> snapshots preserve end-state and per-round file changes
        +--> honeypots and traffic detectors emit evidence
        |
        v
anti-cheat aggregation -> suspicion events/report -> human review
```

### Round lifecycle

1. Import the event and challenge packages. `challenge.yml` is the common manifest for uploads, GitHub imports, and repo-binding resyncs.
2. Validate/review the challenge and build the service/checker images or use the documented self-hosted/BYOC path.
3. At game start, warmup allows services and teams to stabilize. A&D then advances in ticks.
4. Each team receives its own instance. The defender patches its own service; the attacker targets opponent instances only through the game network.
5. The SLA checker exercises normal functionality, not the intentionally vulnerable path. A patched service must remain usable.
6. Flags are rotated/lived for configured ticks. Attack results require extraction plus submission through the platform workflow; a local toolkit must not guess platform endpoints.
7. The platform records health, attacks, scoring, live events, suspicious access, traffic, and changed-file evidence.
8. At game end, snapshots preserve a heavy container tarball and a lightweight per-round change manifest for forensics.

## Challenge authoring conclusions

The example event uses:

- `type: AttackDefense`
- event-level `ad.tickSeconds`, `flagLifetimeTicks`, `warmupSeconds`, `resetCooldownMinutes`, and snapshot download control
- `ad.selfHosted: true` for BYOC/tunnel relay
- challenge container limits and exposed service port
- `ad.allowEgress`, `allowSelfReset`, and optional `sshRequiresFlag`
- a separate checker image built from the checker directory

The sample challenge intentionally separates:

- vulnerable application behavior
- functionality-only SLA checker
- attacker solver/reference exploit
- container build files

The `ledger-forge` sample demonstrates a chained web path: public-key exposure → JWT algorithm-confusion → admin authorization → SSTI. The `vault-keeper` sample demonstrates a memory-safety path: dangling slot pointer → reallocation/metadata confusion → arbitrary read. These are references for local fixtures and regression tests, not targets to run here.

Important parser constraint from the documentation: keys are camelCase; unknown keys are ignored. A typo can silently remove intended behavior. The architecture therefore needs schema validation before accepting manifests.

## Access, snapshots, and evidence

The fork's access plane is private rather than public exposure:

- WireGuard puts the player's machine on challenge subnets.
- SSH jump access is keyed and scoped to the team's own container.
- Access is revoked when membership is removed.

Snapshots are two artifacts with different purposes:

- end-of-game `docker commit`/`docker save` tarball in blob storage
- deduplicated per-round file-change manifest in the database

This implies our local toolkit should produce deterministic manifests and evidence bundles, but must not implement destructive container operations by default.

## Honeypots and anti-cheat

Honeypots are observation signals, not automatic blocking. The docs describe HTTP baits and low-interaction protocol/port baits. A hit is attributed where possible, forwarded to suspicion/live-feed systems, and left for organizer review.

Anti-cheat is an evidence pipeline, not a verdict engine:

- detectors call a common suspicion-event service
- events have typed rule codes, weights, related participation, details, and timestamps
- score is a running aggregate, but hard signals require corroboration
- traffic/flag-egress evidence has team-boundary limitations
- reports should be read as structured evidence, not as an automatic disqualification

The local implementation should model this as `Evidence -> Detector -> Correlation -> Report`, with confidence and provenance. Avoid treating shared IP, timing similarity, or a honeypot hit alone as proof.

## High-end local architecture proposal

```text
attnndef/
  src/attnndef/
    core/       typed target, round, manifest, evidence, verdict models
    attack/     strategy registry, bounded concurrent runner, extractor, submit adapter
    defense/    SLA probes, patch plans, health checks, replay and rollback manifests
    detection/  honeypot/flow/access detectors and suspicion scoring
    manifest/   challenge.yml validation and normalized model
    evidence/   JSONL evidence sink, hashes, provenance, redaction
    fixtures/   localhost web/pwn-style deterministic mock services
    cli.py      inspect, validate, attack --dry-run, defend --dry-run, report
  config/       local-only target and policy files
  docs/         source captures, workflow, architecture, threat model
  tests/        unit, contract, fixture, property, and replay tests
```

### Attack strategies

Use a registry and a common interface rather than one monolithic solver. Initial strategy families:

1. HTTP/API reconnaissance with strict allowlist and rate limit.
2. Auth/session parser and authorization differential checks.
3. Web template/injection regression checks against a local fixture.
4. File/path and serialization probes against a local fixture.
5. Binary protocol/menu state-machine strategy against a local fixture.
6. Flag extraction and format validation.
7. Replay strategy from recorded evidence.

Every strategy must declare capability, required fixture, safety class, timeout, and whether it is `DRY-RUN` or `VERIFIED`. No strategy gets an external target implicitly.

### Defense strategies

1. Manifest/schema validation before build.
2. SLA contract probes for health and legitimate core flow.
3. Patch plan with diff preview, backup/hash, apply, and rollback.
4. Regression matrix proving the patch closes the bug without breaking SLA.
5. Container policy checks: privilege, filesystem, egress, resource limits, secrets.
6. Artifact/change manifest and replayable evidence.
7. Suspicion review report with hard/soft signal separation.

### Safety invariants

- Default target policy is localhost only (`127.0.0.1`, `localhost`, `::1`).
- External hostnames, public IPs, VPN peers, SSH endpoints, and platform submit APIs are rejected unless an explicit future policy enables them.
- Attack commands default to `DRY-RUN`; fixture execution is an explicit separate mode.
- No solver module may submit a flag or contact a platform endpoint.
- Evidence stores hashes and redacted metadata, never credentials or raw secrets.
- Destructive patch/container actions require explicit opt-in and a rollback artifact.

## Implementation order

1. Normalize and validate challenge manifests with negative tests for silently ignored/misspelled keys.
2. Complete typed models and policy gate.
3. Add local web and TCP fixtures with vulnerable and patched modes.
4. Implement strategy registry and bounded runner; keep solver adapters inert.
5. Implement defense health/SLA probes and patch/replay plans.
6. Implement evidence, suspicion scoring, and report correlation.
7. Add snapshot/change-manifest generation without deployment.
8. Add property, contract, and end-to-end localhost tests.
9. Only after review, consider a separate opt-in integration adapter for a controlled lab platform.

## What is still not verified

- Exact deployment/provider behavior in this repository was not executed.
- No live GZCTF platform was contacted.
- No external target, remote solver, VPN, SSH, flag submission, or deployment action was run.
- The public reference solvers were read as design examples only.
