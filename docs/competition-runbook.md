# Competition Runbook: GZCTF Attack & Defense

This is the operator playbook for the `attnndef` toolkit. It describes what to do during a real, explicitly authorized A&D competition. The repository remains platform-neutral: GZCTF discovery, authentication, target refresh, and flag submission must be supplied through a separately reviewed adapter whose exact API contract is verified from the running event. The built-in `submit` command is local evidence only.

Never paste bearer tokens, private keys, flags, or team credentials into source code or evidence files.

## 0. Mental model

Each round is a loop, not a one-time solver run:

```text
refresh targets + round metadata
        |
        +--> defensive lane: snapshot -> inspect -> patch -> reload/restart
        |                    -> health/SLA -> exploit replay -> regression
        |
        +--> offensive lane: group targets by challenge
                             -> bounded solver wave
                             -> extract/validate/deduplicate flags
                             -> reviewed platform adapter submits
                             -> record accepted/rejected/expired result
        |
        +--> evidence lane: JSONL observations, latency, errors, patch IDs,
                             change manifest, and suspicious signals
        |
        +--> scoreboard/live-feed review -> refresh target map
```

The defender owns its instances; the attacker targets opponent instances. The checker tests legitimate functionality, so patching must close the root cause without breaking the normal SLA flow. GZCTF fork features such as WireGuard, SSH, snapshots, honeypots, traffic analysis, and anti-cheat are platform features; this repository models the local operator workflow but does not guess their API.

## 1. Before the contest

Create an isolated virtual environment and run the complete suite:

```bash
cd /home/claritys/ctf/attNdef
python -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/pytest -q
```

If the optional `test` extra is not available in the event environment, install `pytest` in the venv and run the suite. Keep a clean Git checkpoint:

```bash
git status --short
git tag -a pre-contest -m 'pre-contest checkpoint'
```

Prepare a private working copy of the competition target registry. Do not commit it if it contains real IPs, ports, tokens, or credentials:

```bash
cp config/targets.example.json config/targets.json
chmod 600 config/targets.json
```

The registry should contain two explicit sets:

- `role: own`: services to defend.
- `role: enemy`: opponent services that the competition rules authorize attacking.

Treat target addresses as ephemeral. Refresh them every round from the official event mechanism; never carry an old address across a reset without checking it.

## 2. First minutes: establish a baseline

1. Confirm the official rules, tick length, warmup, flag lifetime, submission limits, allowed egress, and reset policy.
2. Confirm the access plane (VPN and/or SSH) using the official client instructions. Do not store private keys in this repository.
3. Populate the local registry from the verified event data.
4. Run discovery and save the baseline:

```bash
.venv/bin/attnndef --registry config/targets.json discover --role own
.venv/bin/attnndef --registry config/targets.json discover --role enemy
```

5. Run defender health checks first. Health functions must be challenge-specific and must exercise only legitimate functionality.

```bash
.venv/bin/attnndef --registry config/targets.json health \
  --role own --check-fn competition_checks.web:health
```

6. Do not attack during warmup unless the rules explicitly allow it. A failed baseline is a defense incident, not an exploit opportunity.

## 3. Defensive lane: per round

The order is deliberate because a bad patch can lose more points than an unpatched service.

### 3.1 Snapshot and inspect

Capture the service version, configuration hash, process state, listening ports, and a redacted change manifest. The platform's heavyweight container snapshot is handled by the platform; locally record only evidence and rollback material.

```bash
.venv/bin/attnndef --registry config/targets.json patch \
  --target-id own-web \
  --search 'DEBUG=true' --replace 'DEBUG=false' --mode dry-run
```

The dry run must be reviewed before applying. Use the smallest root-cause fix, not a blanket feature shutdown.

### 3.2 Patch and verify

```bash
.venv/bin/attnndef --registry config/targets.json patch \
  --target-id own-web \
  --search 'DEBUG=true' --replace 'DEBUG=false' --mode apply

.venv/bin/attnndef --registry config/targets.json health \
  --role own --check-fn competition_checks.web:health
```

If the service requires reload/restart, perform that through the authorized team access method, then rerun health. The patcher only changes the declared fixture/config path; it does not pretend to restart an unknown service.

### 3.3 Regression gate

A patch is not accepted until both conditions hold:

- the exploit replay no longer succeeds;
- the legitimate checker flow still succeeds.

```bash
.venv/bin/attnndef --registry config/targets.json replay \
  --target-id own-web \
  --attack-fn competition_attacks.web:attack_fn \
  --check-fn competition_checks.web:health
```

For multiple vulnerabilities, maintain one strategy and one regression test per root cause. Record the strategy ID, diff, backup path, health result, and replay result in evidence.

### 3.4 Rollback

Rollback only the exact backup belonging to the patch plan:

```bash
.venv/bin/attnndef --registry config/targets.json rollback \
  --target-id own-web \
  --backup-path backups/own-web-<timestamp>.bak \
  --config-path fixtures/own-web/service.ini
```

Then reload/restart through the authorized mechanism and verify health. A rollback is preferable to leaving a service broken.

## 4. Offensive lane: per wave

The offensive runner is intentionally split into four visible stages.

### 4.1 Refresh and group

Refresh the enemy registry from the official event view. Group by challenge and solver variant. Do not scan arbitrary ports or follow platform metadata outside the authorized target list.

```bash
.venv/bin/attnndef --registry config/targets.json discover \
  --role enemy --tag web
```

### 4.2 Run a bounded solver wave

A challenge-specific `attack_fn` receives a target and returns raw output. It must implement its own HTTP/socket timeouts and must not contain platform submission logic.

```bash
.venv/bin/attnndef --registry config/targets.json \
  --sink evidence/wave-$(date +%s).jsonl solve \
  --role enemy \
  --attack-fn competition_attacks.web:attack_fn \
  --max-workers 4 --timeout 8
```

Start conservatively. Increase concurrency only if the rules and service capacity allow it. Keep separate variants for different implementations instead of turning one solver into an unreviewable chain.

Recommended strategy order:

1. protocol/health confirmation;
2. low-noise endpoint and auth differential checks;
3. challenge-specific exploit primitive;
4. flag extraction and strict format validation;
5. stop immediately after a valid flag.

Do not retry a target indefinitely. Classify each result as solved, no-flag, rejected, timeout, unreachable, or stale-target.

### 4.3 Extract and deduplicate

For raw output that was captured separately:

```bash
.venv/bin/attnndef --sink evidence/extract.jsonl extract \
  --input artifacts/raw-target-output.txt --target-id enemy-web-01
```

Validate the actual event flag format supplied by organizers. The generic `FLAG{...}` default is only a placeholder. Never submit a flag that has not been normalized, length-checked, and deduplicated.

### 4.4 Submit through a reviewed adapter

The repository's built-in command records a local submission intent and explicitly does not contact GZCTF:

```bash
.venv/bin/attnndef submit \
  --target-id enemy-web-01 --flag 'FLAG{redacted-in-docs}'
```

For the real contest, use a separately reviewed `platform_adapter` with credentials loaded from the environment or a secret manager. The adapter must be an explicit opt-in, target the exact official event, use the documented endpoint/schema, batch only normalized flags, and record the platform response without logging tokens or flag values. Do not implement this adapter by guessing from UI text or a conceptual API.

## 5. Tick cadence

Use a human-visible cadence tied to the event tick. A practical pattern is:

```text
T-60..T-45  refresh targets, check own health, review live feed
T-45..T-30  patch/reload own service, run SLA regression
T-30..T-05  run bounded attack wave against enemy instances
T-05..T+00  validate/deduplicate and submit through reviewed adapter
T+00..T+10  inspect accepted/rejected/expired results and evidence
```

Adjust this to the actual flag lifetime and submission limits. Do not run a blind infinite loop; every wave needs a target snapshot, wave ID, concurrency cap, and evidence path.

## 6. Handling GZCTF telemetry and anti-cheat

The fork documentation describes honeypots, container-access signals, flag-egress inspection, shared-IP correlation, solve-sequence similarity, and suspicion reports. Treat them as evidence:

- Do not touch honeypot paths or ports during legitimate solving.
- Keep attack traffic within the intended challenge protocol.
- Avoid unnecessary flag re-requests and broad probing.
- Preserve timestamps and target identity for every attack result.
- Never assume a shared IP or timing similarity proves collusion.
- If reviewing a report, correlate soft signals with hard evidence such as unauthorized container access, wrong-flag leakage, or flag-egress details.

The platform's live feed is operational telemetry, not a replacement for local evidence. Store local JSONL records with wave, challenge, target ID, solver variant, status, latency, and redacted error details.

## 7. Failure handling

- `unreachable`: check VPN/access, service state, and target freshness; do not immediately increase retries.
- `timeout`: reduce concurrency, inspect service health, then retry once within the wave budget.
- `stale-target`: refresh registry; never reuse the old address.
- `no flag`: preserve raw output metadata, classify the exploit stage, and move to the next target.
- `SLA failure`: stop offensive work on that own service, rollback or repair, and rerun legitimate checks.
- `rejected/expired`: record the platform result; do not resubmit blindly.
- `patch replay still succeeds`: rollback if needed, re-read the vulnerability root cause, and do not claim the service is defended.

## 8. End-of-round report

Every round should leave:

- registry snapshot hash and wave ID;
- own-service health before/after patch;
- patch strategy, diff, backup, and rollback status;
- exploit replay result;
- attack counts by challenge and outcome;
- extracted/submitted/accepted/rejected/expired counts;
- evidence file path and redaction status;
- unusual traffic or suspicion observations;
- next-round action list.

A winning workflow is repeatable and observable: defend SLA first, attack only authorized opponent instances, submit only verified flags, and preserve enough evidence to diagnose every failure.

## Local rehearsal

Before using any real competition adapter, rehearse the complete sequence against the repository's localhost fixtures:

```bash
.venv/bin/pytest -q
.venv/bin/attnndef --registry config/targets.example.json discover --role own
```

The public reference solvers and GZCTF platform sources in `refs/` are for understanding challenge and platform models. They are not invoked by this runbook.
