# Maintainer Notes

## Release checklist

- [ ] Run `.venv/bin/pytest -q`.
- [ ] Confirm `config/targets.json` and `evidence/` are ignored.
- [ ] Search for credentials, tokens, private keys, and real flags.
- [ ] Review README and `docs/quickstart.md` from a clean checkout.
- [ ] Confirm live submission remains opt-in and dry-run is demonstrated.
- [ ] Review changes and create a rollback-capable Git commit.
- [ ] Push only after checking the staged file list.

## Public learning quality checklist

- [ ] A beginner can install and run tests.
- [ ] Every command has a purpose and expected result.
- [ ] Every lab has both attack and defense objectives.
- [ ] Intentionally vulnerable code is isolated and labeled.
- [ ] No unverified platform API is presented as fact.
- [ ] Safety boundaries are visible before exploit instructions.
- [ ] Contributors have a module template and test expectations.
