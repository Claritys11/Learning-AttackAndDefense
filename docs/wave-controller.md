## Multi-solver wave controller and submission

When the competition's endpoints and submission schema have been verified, use
`wave` to orchestrate multiple challenge solvers. Each solver is an explicit
`module:function`; the controller runs them against the declared `enemy`
targets, extracts/deduplicates flags, and then hands them to a submitter.

Dry-run first:

```bash
.venv/bin/attnndef --registry config/targets.json \
  --sink evidence/wave.jsonl wave \
  --solver web=competition_attacks.web:attack_fn \
  --solver pwn=competition_attacks.pwn:attack_fn \
  --endpoint https://official-event.example/api/verified-submit
```

`wave` is dry-run even with an endpoint. It will not send a request until the
explicit live gate is supplied:

```bash
export ATTNDEF_SUBMIT_TOKEN='loaded-out-of-band'
.venv/bin/attnndef --registry config/targets.json \
  --sink evidence/wave.jsonl wave \
  --solver web=competition_attacks.web:attack_fn \
  --solver pwn=competition_attacks.pwn:attack_fn \
  --endpoint https://official-event.example/api/verified-submit \
  --token-env ATTNDEF_SUBMIT_TOKEN \
  --live-submit
```

The endpoint must be HTTPS or localhost. The token is read only from the
specified environment variable and is never printed. Submission is batched,
deduplicated, and the response status is recorded as structured output. The
endpoint path and JSON schema are intentionally not guessed; replace the
example only after confirming them from the official competition/API source.

The safer local test uses the included fixture solver:

```bash
.venv/bin/attnndef --registry config/targets.example.json wave \
  --solver fixture=tests.fixture_solver:always_flag \
  --endpoint http://127.0.0.1:9999/submit
```

This must remain dry-run in local rehearsal.
