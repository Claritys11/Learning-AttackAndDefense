# Operator Situational Awareness

Phase 7 introduces the **Operator Situational Awareness** subsystem. Its sole purpose is **consolidation, correlation, and visibility**: empowering the operator to immediately answer critical operational questions from a single cockpit view without introducing autonomous execution or conflicting sources of truth.

---

## 1. Architectural Role & Invariants

Situational Awareness is strictly a **read-only, aggregation, and presentation** layer:

```text
Mission Context        ──┐
Workflow Context       ──┼──▶ SituationalAwarenessService ──▶ MissionAwarenessView / TargetAwarenessView
Target Intelligence    ──┤     (Pure aggregation, no writes)    (CLI + Interactive UI + JSON)
Operations & SLA       ──┤
LocalSink Evidence     ──┘
```

### Core Invariants
1. **Zero State Mutation**: Situational awareness queries never mutate database records, advance rounds, create workflows, or execute tools.
2. **Not a New Source of Truth**: All metrics and summaries are derived dynamically on demand from existing authoritative sources (`OperationService`, `TargetService`, and `LocalSink`).
3. **No Autonomous Actions**: The system never initiates autonomous attacks, exploit delivery, flag submission, or network scans.
4. **Zero Plaintext Flag Persistence**: Flag representations show strictly SHA-256 fingerprints and masked previews (`flag{...1a2b}`). Plaintext flags are never rendered in views or JSON exports.
5. **Deterministic Aggregation**: All timelines, diffs, and health trajectories are calculated via deterministic rules without probabilistic or heuristic speculation.

---

## 2. Domain & View Models

Defined in `attnndef.operations.awareness_models`:

### `MissionAwarenessView`
Aggregates complete operational context around a focused Mission:

* **Mission Identity**: `mission_id`, `title`, `objective`, `status`, `target_id`, `service_port`, `service_protocol`, `created_at`, `completed_at`, `notes`.
* **Target Posture**: `target_name`, `target_host`, `target_role` (`own` | `enemy`).
* **Workflow Context**: `workflow_id`, `workflow_title`, `workflow_status`, `round_id`, `session_id`.
* **Intelligence Posture**:
  * `initial_observation_id`: Starting baseline observation reference.
  * `latest_observation_id`: Latest recorded observation from Target Intelligence.
  * `is_service_open_now`: Boolean indicating whether the service port/protocol is currently active in the latest scan.
  * `diff_summary`: Changes (services added, removed, or modified) between baseline and latest observations.
* **Service Health & SLA**:
  * `sla_history`: Recent SLA observations for this specific target and service.
  * `last_sla_status`: Most recent status (`OK`, `MUMBLE`, `OFFLINE`).
  * `health_trajectory`: Deterministic status trajectory (`healthy`, `degrading`, `offline`, `recovering`, `unknown`).
  * `avg_latency_ms`: Average observed latency across recent checks.
* **Operations Breakdown**:
  * Counts and status breakdowns of actions, attacks, defenses, flags, and SLA checks.
* **Flag State**:
  * Observed, validated, submitted, and rejected counts with masked previews.
* **Timeline & Evidence**:
  * Chronological stream of all activity linked to the mission.
  * Correlated `LocalSink` evidence artifacts linked to actions or target.

### `TargetAwarenessView`
Aggregates posture across all services, missions, and operational records for an entire target host.

### `EvidenceDetailView`
Provides safe inspection of full payloads from `LocalSink` evidence items.

---

## 3. Deterministic Health Trajectory

Health trajectory reflects service availability trends based on chronological SLA observations:

| Recent SLA Observations | Health Trajectory | Description |
| :--- | :--- | :--- |
| `[OK] ──▶ [OK]` | `HEALTHY` | Service has consistently passed availability checks. |
| `[OK] ──▶ [OFFLINE/MUMBLE]` | `DEGRADING` | Service was previously healthy but has failed its latest check. |
| `[OFFLINE] ──▶ [OFFLINE]` | `OFFLINE` | Service remains consistently offline or unserviceable. |
| `[OFFLINE/MUMBLE] ──▶ [OK]` | `RECOVERING` | Service was previously down/unstable but has recovered to healthy state. |
| No checks recorded | `UNKNOWN` | No local SLA observations recorded for this service. |

---

## 4. CLI Usage

The `awareness` command group provides quick terminal inspection and machine-readable JSON:

### Mission Situational Awareness
```bash
# Terminal formatted dashboard
attnndef awareness --mission 550e8400

# JSON formatted export
attnndef awareness --mission 550e8400 --json
```

Example human-readable output:
```text
SITUATIONAL AWARENESS: MISSION #550e8400
─────────────────────────────────────────────────────────────────
[CONTEXT]
  Title:     Inspect HTTP service
  Objective: Analyze endpoint vulnerabilities
  Target:    enemy-01 (10.0.0.1) [role: enemy]
  Service:   TCP/8080
  Status:    IN_PROGRESS | Workflow: #12 (Web Investigation)

[INTELLIGENCE POSTURE]
  Baseline:  Obs #29
  Current:   Obs #34
  Service:   OPEN
  Diff:      ADDED: 3306/tcp mysql (1 services added)

[HEALTH & SLA TRAJECTORY]
  Status:    OK (Trajectory: HEALTHY)
  Avg Lat:   20.5 ms

[OPERATIONS SUMMARY]
  Actions:   1
  Attacks:   1 [SUCCESS:1]
  Defenses:  1 [COMPLETED:1]
  Flags:     1 observed, 0 submitted, 0 rejected

[RECENT ACTIVITY]
  20:15:30  [RECON       ] Port scan 8080 [completed]
  20:16:12  [ATTACK      ] sqli [success]

[CORRELATED EVIDENCE]
  1 evidence artifact(s) correlated:
  - [ev-recon-8080] tool_nmap (OK): Nmap port scan successful
─────────────────────────────────────────────────────────────────
```

### Target Situational Awareness
```bash
# Terminal formatted target dashboard
attnndef awareness --target enemy-01

# JSON export
attnndef awareness --target enemy-01 --json
```

### Evidence Inspection
```bash
# Inspect specific evidence item
attnndef awareness --evidence ev-recon-8080
attnndef awareness --evidence ev-recon-8080 --json
```

---

## 5. Interactive Cockpit Integration

Within the Mission Cockpit (`attnndef console` $\to$ `A&D Operations` $\to$ `Missions` $\to$ `Open Mission`), operators have two direct actions:

* **11. Situational Awareness Dashboard**: Displays the consolidated context, intelligence diffs, health trajectory, and operation metrics.
* **12. Inspect Correlated Evidence**: Lists all evidence artifacts linked to the active mission and displays full structured payload details on selection.
