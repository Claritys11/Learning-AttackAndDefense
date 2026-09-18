# Phase 3H — Intelligence Boundary Hardening

Phase 3H establishes the authorization seam before attack functionality exists.

```text
Target intelligence
        ↓ read-only input
ExecutionBoundary
        ↓ explicit operation authorization
future attack execution
```

`ExecutionBoundary` delegates target/network/exclusion checks to the authoritative `Scope`. Attack authorization additionally requires the target role to be `ENEMY`. Intelligence authorization can read any target permitted by its configured scope and does not imply attack permission.

This phase does not execute attacks or create an attack engine. It adds only a reusable contract and tests proving that rejected targets fail before the Nmap runner is reached. Future attack services must receive an `ExecutionBoundary` and call `authorize_attack()` immediately before side effects.
