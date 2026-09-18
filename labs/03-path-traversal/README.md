# Lab 03 — Path Traversal

Goal: identify unsafe path composition, prove unauthorized file access in a local fixture, then enforce a safe canonical path boundary without breaking normal file access.

## Progression

- L1: identify the file input and read sink.
- L2: reproduce a boundary escape using a fixture-owned harmless file.
- L3: solve without source using endpoint behavior.
- L4: patch canonicalization plus containment/allowlist checks.
- L5: preserve normal downloads and prove replay failure.

## Hint ladder

- Hint 0: no hint.
- Hint 1: compare a valid file name with a nested path.
- Hint 2: inspect how the server joins the base directory and user input.
- Hint 3: normalization can change the meaning of a path.
- Hint 4: verify the resolved path remains below the intended root.
- Hint 5: test symlink and encoded-separator cases in the fixture.

## Completion gate

- [ ] Access boundary mapped.
- [ ] Harmless fixture file used as proof.
- [ ] Canonical containment patch written.
- [ ] Normal file flow passes.
- [ ] Replay fails.
- [ ] Evidence contains no real secrets.
