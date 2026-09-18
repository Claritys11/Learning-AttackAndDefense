# Lab 04 — Authentication Bypass

Goal: separate authentication from authorization and build an auth matrix for a local fixture.

## Tasks

1. Map anonymous, user, and admin behavior for every route.
2. Record token/session creation, validation, expiry, and role checks.
3. Identify a broken trust assumption in the fixture.
4. Reproduce the unauthorized action locally.
5. Patch verification and authorization at the server boundary.
6. Confirm normal login and least-privilege behavior remain intact.

## Hint ladder

- Hint 0: no hint.
- Hint 1: make a table of actor × endpoint × expected result.
- Hint 2: inspect whether the server verifies identity and role independently.
- Hint 3: never trust a client-provided role or unchecked token claim.
- Hint 4: validate issuer, audience, expiry, algorithm, signature, and server-side authorization.
- Hint 5: replay the same request as anonymous, user, and admin after patching.

## Completion gate

- [ ] Auth matrix complete.
- [ ] Unauthorized behavior reproduced locally.
- [ ] Root cause and trust boundary documented.
- [ ] Patch preserves valid users' flow.
- [ ] Unauthorized replay fails.
