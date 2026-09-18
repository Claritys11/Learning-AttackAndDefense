# Lab 02 — Command Injection

Goal: recognize an unsafe command construction, reproduce it only in the local fixture, patch the root cause, and preserve the normal health contract.

Scope: intentionally vulnerable local fixture. Never change the target to a public host.

## Progression

- L1: inspect the source and identify input, validation, and command sink.
- L2: reproduce the behavior with hints.
- L3: write a minimal bounded PoC.
- L4: replace the unsafe construction with a safe argument API/allowlist and keep normal behavior.
- L5: complete the attack → patch → SLA → replay loop under a timer.

## Notebook task

Copy `docs/attack-notebook-template.md` here as `notes.md`. Fill the data flow before reading a solution.

## Hint ladder

- Hint 0: no hint.
- Hint 1: follow user input from the route to the process boundary.
- Hint 2: inspect how arguments are joined.
- Hint 3: distinguish a command name allowlist from string filtering.
- Hint 4: the dangerous operation is shell interpretation of user-controlled data.
- Hint 5: use an argument list and strict validation; do not rely on escaping alone.

## Completion gate

- [ ] Vulnerable behavior reproduced locally.
- [ ] Root cause documented.
- [ ] Patch is minimal and idempotent.
- [ ] Legitimate health/SLA behavior passes.
- [ ] Original replay fails after patch.
- [ ] Rollback tested.
