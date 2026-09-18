# Quick Start: Learning A&D Tools

This guide gets a new learner from clone to a safe local rehearsal in minutes.

## 1. Install

```bash
git clone https://github.com/Claritys11/Learning-AttackAndDefense.git
cd Learning-AttackAndDefense
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m pip install pytest
```

Verify installation:

```bash
.venv/bin/attnndef --help
.venv/bin/pytest -q
```

## 2. Understand the target file

Copy the safe example before editing:

```bash
cp config/targets.example.json config/targets.json
```

Each target has an ID, host, port, role, tags, and optional metadata. Use:

- `own`: a service you defend.
- `enemy`: a service you are authorized to attack.

Real `config/targets.json` is ignored by Git. Never commit competition targets, tokens, or flags.

## 3. Inspect targets

```bash
.venv/bin/attnndef --registry config/targets.example.json discover
.venv/bin/attnndef --registry config/targets.example.json discover --role own
.venv/bin/attnndef --registry config/targets.example.json discover --role enemy
```

This command only reads the registry. It does not scan.

## 4. Run the local tests

```bash
.venv/bin/pytest -q
```

Tests cover target loading, flag extraction, bounded attacks, health checks, patch/rollback, replay, and the multi-solver controller.

## 5. Run one solver

A solver is a normal Python function with this contract:

```python
def attack_fn(target) -> str:
    # Use only an authorized target.
    # Set HTTP/socket timeouts inside the function.
    # Return raw output; do not submit here.
    return "observation or FLAG{...}"
```

Run it against declared enemy targets:

```bash
.venv/bin/attnndef \
  --registry config/targets.json \
  --sink evidence/solve.jsonl \
  solve \
  --role enemy \
  --attack-fn my_solvers.web:attack_fn \
  --max-workers 2 \
  --timeout 8
```

The runner records success, flag, timing, and sanitized error metadata. Keep solver logic separate from platform submission.

## 6. Run multiple solvers with `wave`

Use one command to coordinate challenge-specific solvers:

```bash
.venv/bin/attnndef \
  --registry config/targets.json \
  --sink evidence/wave.jsonl \
  wave \
  --solver web=my_solvers.web:attack_fn \
  --solver pwn=my_solvers.pwn:attack_fn \
  --max-workers 4 \
  --timeout 8
```

`wave` runs each approved solver, extracts valid flags, deduplicates them, and prints a structured summary.

## 7. Submission modes

Default mode is dry-run. Even when an endpoint is supplied, nothing is sent:

```bash
.venv/bin/attnndef \
  --registry config/targets.json \
  wave \
  --solver web=my_solvers.web:attack_fn \
  --endpoint https://OFFICIAL-VERIFIED-ENDPOINT
```

A live endpoint is allowed only after you verify the official competition schema, authorization, rate limits, and scope. Then load the token out-of-band:

```bash
export ATTNDEF_SUBMIT_TOKEN='do-not-paste-this-in-source'
.venv/bin/attnndef \
  --registry config/targets.json \
  wave \
  --solver web=my_solvers.web:attack_fn \
  --endpoint https://OFFICIAL-VERIFIED-ENDPOINT \
  --token-env ATTNDEF_SUBMIT_TOKEN \
  --live-submit
```

The endpoint must be HTTPS or localhost. The token is not printed. Do not use live submission in a lab.

## 8. Defense workflow

Preview a patch first:

```bash
.venv/bin/attnndef --registry config/targets.json patch \
  --target-id own-web \
  --search 'DEBUG=true' \
  --replace 'DEBUG=false' \
  --mode dry-run
```

Apply only after reviewing the diff:

```bash
.venv/bin/attnndef --registry config/targets.json patch \
  --target-id own-web \
  --search 'DEBUG=true' \
  --replace 'DEBUG=false' \
  --mode apply
```

Then run the service health check and exploit replay. A successful defense must both close the exploit and preserve the legitimate SLA flow.

## 9. Evidence and cleanup

Evidence is local and ignored:

```text
evidence/*.jsonl
```

Review it before deleting. Never share files containing real flags, credentials, private target addresses, or tokens.

## Common mistakes

- Running `solve` before setting the correct `role`.
- Hardcoding a target IP or port in a solver.
- Putting submission code inside an exploit.
- Applying a patch without dry-run, backup, health, and replay.
- Treating a timeout as proof that a target is patched.
- Committing `config/targets.json`, `.env`, or `evidence/`.
- Assuming GZCTF fork APIs match upstream. Verify the exact event API first.

For the full learning sequence, read `docs/ad-learning-roadmap.md`. For competition cadence, read `docs/competition-runbook.md`.
