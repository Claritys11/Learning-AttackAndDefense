# Phase 3 Recon Adapters

The recon boundary is intentionally local-first and scope-gated:

```text
Scope → Adapter → ToolRunner → Parser → Observation → TargetService
```

`ToolRunner` executes argument lists only, captures output, normalizes missing executables, and kills the whole process group on timeout.

`NmapAdapter` accepts only validated numeric port lists/ranges and requires the target to pass `Scope` before execution. `DiscoveryAdapter` accepts a CIDR only when it is contained by configured scope networks. Discovery creates `UNKNOWN` targets; it never infers `ENEMY`.

No live competition target is configured or scanned by this repository. Use fake runners in tests or explicitly configured localhost fixtures.
