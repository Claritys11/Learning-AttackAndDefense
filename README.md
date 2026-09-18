# Learning A&D

A community-oriented, local-first Attack & Defense learning repository for LKS-style practice and GZCTF/TCP1P-compatible competition workflows.

> Learn the vulnerability, attack the lab, patch the root cause, preserve the SLA, and prove the fix.

## What this project teaches

- Enumeration and service/asset mapping.
- CVE reproduction and mitigation.
- Linux and Windows administration/security.
- SSH, VPN, OAuth2/OIDC, and Active Directory fundamentals.
- Source-code review and vulnerability modeling.
- Privilege escalation in isolated labs.
- Event, process, authentication, and network monitoring.
- Data-exfiltration modeling and egress control.
- Firewall, account, password, and scheduler policy.
- A&D round operations: own-service defense, opponent-service attack, SLA, scoring, evidence, and rollback.

This is an educational project, not a production security platform. Use only against fixtures, VMs, containers, or competition targets where you have explicit authorization.

## Start here

1. Read `docs/quickstart.md` for the shortest working setup.
2. Read `docs/tools-guide.md` for the command map and function contracts.
3. Read `docs/ad-learning-roadmap.md` for the 12-week learning path.
4. Read `docs/competition-runbook.md` for the competition-time operating flow.
5. Read `docs/gzctf-ad-workflow-analysis.md` for the GZCTF/TCP1P model.
6. Run the local test suite.
7. Build one lab module using the six-step cycle: concept → observe → reproduce → attack → defend → verify.

```bash
git clone <repository-url>
cd attNdef
python -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m pip install pytest
.venv/bin/pytest -q
```

Expected current baseline: all repository tests pass.

## Repository map

```text
src/attnndef/       reusable attack/defense orchestration library
  core/             typed targets, results, evidence, patch plans
  attack/           extractor, bounded runner, multi-solver wave, submit adapter
  defense/          health, patch, rollback, exploit replay
  io/               structured logs and append-only local evidence
  cli.py            discover, solve, wave, extract, submit, patch, health, replay
config/             safe example target registry; real registry stays untracked
docs/               roadmap, runbooks, GZCTF research, source captures
labs/               space for community/local learning modules
tests/              unit, fixture, contract, and orchestration tests
```

## Learning workflow

For every topic, create a small isolated lab:

```text
labs/<topic>/
  README.md             learning objective and threat model
  vulnerable/           intentionally vulnerable fixture
  patched/              expected fixed version
  attack.py             bounded PoC against the fixture only
  defense.md            root cause and mitigation
  tests/                exploit, regression, and SLA tests
  evidence/             ignored local observations
```

A module is complete only when:

- the vulnerable behavior is reproducible;
- the attack has a clear precondition and observable impact;
- the root cause is explained;
- the patch is minimal and idempotent;
- legitimate functionality still passes;
- exploit replay fails after patching;
- rollback works;
- secrets are not committed.

## A&D competition model

```text
event/challenge manifest
        -> review/import/build
        -> service instance per team
        -> warmup
        -> repeated round/tick
             |-- own lane: inspect -> patch -> health/SLA -> replay
             |-- attack lane: refresh targets -> solver wave -> extract -> submit
             |-- telemetry: live feed, process, traffic, honeypot, access
             |-- forensics: evidence, change manifest, snapshots
        -> scoring and human review
```

The defender owns its instances. The attacker targets only opponent instances listed by the authorized competition mechanism. The checker exercises the normal service flow, so a patch that simply disables the service is a failed defense.

## CLI examples

Local registry inspection:

```bash
.venv/bin/attnndef --registry config/targets.example.json discover --role own
```

Defense dry-run:

```bash
.venv/bin/attnndef --registry config/targets.json patch \
  --target-id own-web --search 'DEBUG=true' \
  --replace 'DEBUG=false' --mode dry-run
```

Multi-solver wave, dry-run submission:

```bash
.venv/bin/attnndef --registry config/targets.json \
  --sink evidence/wave.jsonl wave \
  --solver web=competition_attacks.web:attack_fn \
  --solver pwn=competition_attacks.pwn:attack_fn \
  --endpoint https://OFFICIAL-VERIFIED-ENDPOINT
```

The endpoint must be explicitly verified from the official event/API. Without `--live-submit`, no submission request is sent. Credentials are read from an environment variable, never committed or printed.

## Safety and privacy defaults

- Real target registry, evidence, archives, references, `.env`, and virtual environments are ignored.
- No internet-wide scanning or automatic target discovery is included.
- No exploit runs during installation or tests.
- Submission is dry-run unless explicitly enabled.
- Live adapters must be separately reviewed for endpoint, schema, authorization, rate limits, and event scope.
- Logs should record status, timing, and provenance, not tokens, passwords, or raw flags.
- Honeypot/anti-cheat signals are evidence for review, not automatic guilt.

## Documentation index

- `docs/quickstart.md` — get started and run the tools.
- `docs/tools-guide.md` — command map, contracts, and safety gates.
- `docs/ad-learning-roadmap.md` — LKS 2024/2025-aligned learning plan.
- `docs/competition-runbook.md` — round-by-round operator guide.
- `docs/gzctf-ad-workflow-analysis.md` — platform and A&D flow synthesis.
- `docs/wave-controller.md` — multi-solver and submission adapter.
- `docs/architecture-proposal.md` — architecture decisions.
- `docs/ai-consultation.md` — consultation evidence and provenance.
- `docs/source-*.txt` — captured requested documentation pages.

## Contributing a learning module

Prefer small, reviewable labs. Include an objective, prerequisites, safe setup, expected observations, attack explanation, defensive patch, regression test, cleanup, and references. Never include real credentials or unauthorized targets. Label claims as verified, inferred, or unknown when platform behavior is not directly tested.

## License and attribution

Add the final project license before public release. Keep third-party repository licenses and attribution in their respective source projects; this repository does not vendor the ignored `refs/` checkouts.
