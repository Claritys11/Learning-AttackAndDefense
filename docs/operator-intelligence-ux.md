# Phase 3G — Operator Console Intelligence UX

The Targets menu now exposes the existing target-intelligence services without duplicating SQLite or Nmap logic.

```text
Targets
├── List
├── Select
├── Add/Edit/Remove
├── Details
├── History
├── Scan Target
└── Compare Observations
```

The console accepts injected `ReconService` and `Scope` instances. Scans therefore follow the existing boundary:

```text
InteractiveConsole → ReconService → Scope/NmapAdapter → Observation → TargetService
```

A scan displays the persisted observation and compares it with the previous observation using `IntelligenceDiff`. Explicit observation comparison also uses `compare_observations()` directly; it never parses rendered text.

The default console does not claim that scanning is available unless a recon service and scope are configured. Tool errors and scope rejection are shown as concise operator messages. Tests use fixture XML and fake runners only.
