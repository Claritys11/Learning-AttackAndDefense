# Operator Mission & Service Workflow

Phase 6 introduces the **Operator Mission & Service Workflow** subsystem, transforming ATTNNDEF's operational core and tool layers into a practical operator cockpit for real Attack & Defense engagements.

---

## 1. Workflow vs Mission

ATTNNDEF maintains a clear conceptual hierarchy between high-level operational activities and focused technical objectives:

```text
┌─────────────────────────────────────────────────────────────┐
│                        WorkflowRun                          │
│        (Container for broader operator activity)            │
│         e.g. "Investigate enemy services in round #1"       │
└──────────────────────────────┬──────────────────────────────┘
                               │ 1:N
        ┌──────────────────────┴──────────────────────┐
        ▼                                             ▼
┌──────────────────────────────┐        ┌──────────────────────────────┐
│           Mission            │        │           Mission            │
│ Target: enemy-03             │        │ Target: enemy-04             │
│ Service: TCP/8080 HTTP       │        │ Service: TCP/22 SSH          │
│ Objective: Investigate 500   │        │ Objective: Inspect exposed   │
│            endpoint error    │        │            configuration     │
└──────────────────────────────┘        └──────────────────────────────┘
```

* **Workflow**: A container for broader operator activity across targets, rounds, or strategic goals.
* **Mission**: A concrete, focused technical objective against a specific **target** and **service** (port and protocol).
* **Hierarchy**: Every Mission belongs to an existing Workflow (`workflow_id`). One Workflow may contain multiple Missions.
* **Boundary**: A Mission does **not** authorize an attack or grant network permissions.

---

## 2. Mission Model & Lifecycle

A Mission tracks an operator's focused engagement around a target and service.

### Domain Model
```text
Mission
├── mission_id             : Unique UUID
├── workflow_id            : Reference to parent WorkflowRun
├── target_id              : Reference to target host/role in Target Registry
├── service_port           : Port number (1–65535)
├── service_protocol       : Protocol ("tcp" | "udp")
├── title                  : Operator-assigned objective title
├── objective              : Concrete operational hypothesis
├── status                 : OPEN | IN_PROGRESS | COMPLETED | ABORTED
├── created_at             : Timestamp of mission creation
├── completed_at           : Timestamp of completion or abort
├── notes                  : Operator closing notes / post-mortem
└── initial_observation_id : Optional link to existing Target Intelligence observation
```

### Lifecycle State Machine
```text
      [ create ]
          │
          ▼
       ┌──────┐
       │ OPEN │
       └──┬─┬─┘
  start   │ │ abort
  ┌───────┘ └───────┐
  ▼                 ▼
┌─────────────┐  ┌─────────┐
│ IN_PROGRESS │  │ ABORTED │ (terminal)
└──────┬──┬───┘  └─────────┘
abort  │  │ complete
┌──────┘  └──────┐
▼                ▼
┌─────────┐   ┌───────────┐
│ ABORTED │   │ COMPLETED │ (terminal)
└─────────┘   └───────────┘
```

* **Explicit Operator Transitions**: Transitions are operator-initiated via CLI (`attnndef mission --start/complete/abort`) or Interactive Cockpit.
* **No Autonomous Completion**: A Mission is **never** automatically completed when:
  * An attack succeeds or returns code 0.
  * A flag is recorded or submitted.
  * An SLA check returns OK.
  * A service becomes healthy or patched.
* **Terminal States**: Once `COMPLETED` or `ABORTED`, a mission cannot transition further.

---

## 3. Service & Target Intelligence Context

The Mission Cockpit correlates Target Intelligence **without duplicating data**:

```text
TARGET
  enemy-03 (10.0.0.3) [enemy]

SERVICE
  TCP/8080 HTTP

CURRENT INTELLIGENCE
  Observation: #31
  Services: 22/ssh, 8080/http
  Observed: 2026-09-18 20:00:15

RECENT ACTIVITY
  20:01  RECON         Nmap port scan [completed]
  20:02  OPERATOR      HTTP endpoint inspection [completed]
  20:03  ATTACK        Path traversal record [success]
  20:04  VERIFICATION  Probe traversal endpoint [completed]

FLAGS
  1 observed | 1 submitted

HEALTH
  Last local check: OK
```

### Intelligence Boundary
* Mission **consumes** existing Target Intelligence via `TargetService`.
* Mission does **not** create a duplicate service or target store.
* **Starting Point vs Current Intelligence**: Mission stores `initial_observation_id` as an optional starting point reference, and never stores `current_observation_id`. Current intelligence is always dynamically resolved from Target Intelligence history to prevent dual sources of truth.
* **Target Intelligence Service Validation**:
  * Workflow must exist.
  * Target must exist in registry.
  * Port must be valid (1–65535).
  * Protocol must be valid (`tcp` | `udp`).
  * If `initial_observation_id` is provided:
    * Observation must exist and belong to the mission's `target_id`.
    * Specified port and protocol must exist within the observation's recorded services.
  * If `initial_observation_id` is omitted: Mission creation succeeds without forcing a scan.
* Running a scan inside a mission strictly adheres to:
  $$\text{Scope} \longrightarrow \text{ReconService} \longrightarrow \text{NmapAdapter} \longrightarrow \text{Observation} \longrightarrow \text{IntelligenceDiff}$$
* A newly recorded observation does not automatically mutate mission status.

---

## 4. Attachment Invariants

When operational records (actions, attacks, defenses, flags, SLA observations) are linked to a Mission, ATTNNDEF strictly enforces the following correlation invariants:

```text
Attachment Invariants:

1. Mission must exist.
2. Record must exist.
3. Record session must equal Mission workflow session.
4. If record has target_id:
     record.target_id == mission.target_id
5. If record has workflow_id:
     record.workflow_id == mission.workflow_id
6. If record has mission_id:
     reject conflicting reassignment unless explicit reassignment API exists.
7. Never silently mutate workflow_id during attachment.
```

* **No Silent Workflow Reassignment**: Attachment is strictly a **correlation** operation (`UPDATE ... SET mission_id = ?`). It never mutates `workflow_id` or `target_id`.
* **Conflict Prevention**: Reassigning a record that is already associated with another mission is strictly rejected.

---

## 5. Verification & Tool Execution Workflow

The Mission Cockpit provides an explicit operator verification flow:

```text
Mission Cockpit
      │
      ▼
Record Verification
      │
      ├── Select Parent Action (e.g. Attack or Defense record)
      ├── Run or Record Verification Tool (e.g. HTTP GET or curl)
      ├── Optional SLA Health Observation
      ├── Optional Intelligence Refresh Scan
      └── Compare Observations (IntelligenceDiff)
```

### Tool Execution Architecture
When `Run Tool` is invoked from the Mission Cockpit:

```text
Operator / Mission Cockpit
           │ (Provides context: target, port, workflow_id, mission_id)
           ▼
Existing Tool UI / Canonical Tool Service (NmapService, HttpService, etc.)
           │
           ▼
Scope / ExecutionBoundary (Validates host authorization)
           │
           ▼
ToolRunner (Safe argv execution, POSIX process group, timeout)
           │
           ▼
External Tool Binary
```

Mission does **not** provide a custom `MissionExecutor` and does not bypass existing tool workflows. Tool execution remains the responsibility of the tool layer, and authorization remains strictly bounded by `Scope`.

### Separation of Facts
The system maintains strict independence between operational facts:
$$\text{Defense COMPLETED} + \text{HTTP 200} \neq \text{Defense SUCCESS (inferred)}$$
The operator remains the sole authority to evaluate whether a patch works, whether a vulnerability is closed, and whether a mission is completed.

---

## 6. Security & Execution Boundaries

1. **No Autonomous Attack Planning**: Missions cannot choose exploits, construct payloads, execute scripts, submit flags, or patch systems autonomously.
2. **Context vs Scope Authorization**: Assigning `target_id="enemy-03"` to a mission is organizational metadata. It does **not** authorize network packets. Network tools check `Scope.is_allowed(host)` and `ExecutionBoundary.require_allowed(host)`.
3. **Execution Behind ToolRunner**: All external tool executions run through `ToolRunner` with safe argument vectors, bounded timeouts, and `shell=False`.
4. **Zero Plaintext Flag Persistence**: Raw flags input to a mission are hashed to SHA-256 fingerprints with masked previews (`flag{...12345}`). Plaintext flags are never persisted in SQLite or evidence files.
5. **No Remote Competition Integration**: ATTNNDEF has no remote GZCTF API integration, no automated score claims, and no official SLA authority. All rounds, ticks, and SLAs are operator-recorded local observations.

---

## 7. CLI Usage

### Mission Management
```bash
# Create a mission under a workflow
attnndef mission \
  --create \
  --workflow 550e8400 \
  --target enemy-03 \
  --port 8080 \
  --protocol tcp \
  --title "Investigate HTTP service" \
  --objective "Investigate unexpected endpoint behavior"

# List missions
attnndef mission --list
attnndef mission --list --json

# Show mission details
attnndef mission --show 550e8400

# Start a mission
attnndef mission --start 550e8400

# Complete a mission with notes
attnndef mission --complete 550e8400 --notes "Endpoint confirmed patched"

# Abort a mission with reason
attnndef mission --abort 550e8400 --notes "Target host down"

# View mission chronological timeline
attnndef mission --timeline 550e8400
```

### Correlating Operational Records with `--mission`
```bash
# Record an action under a mission
attnndef action --record --category recon --target enemy-03 --tool nmap --op scan --summary "Port scan" --mission <mid>

# Record an attack attempt under a mission
attnndef attack --record --target enemy-03 --service http/8080 --method "sqli" --status success --mission <mid>

# Record a defense action under a mission
attnndef defense --record --target enemy-03 --service http/8080 --action "input validation" --mission <mid>

# Record a flag under a mission (fingerprint only)
attnndef flag --record "flag{example_flag}" --target enemy-03 --source "curl" --mission <mid>

# Record a local SLA check under a mission
attnndef sla --record --target enemy-03 --service http/8080 --status ok --latency 35 --mission <mid>

# View correlated timeline filtered by mission
attnndef timeline --mission <mid>
```

---

## 8. Interactive Cockpit Flow

Operators can launch the interactive cockpit via `attnndef console`:

```text
ATTACK & DEFENSE OPERATIONS
────────────────────────────
  1. Current Round & Ticks
  2. Operator Actions
  3. Attack Records
  4. Defense Records
  5. Flag State
  6. SLA / Health Observations
  7. Activity Timeline
  8. Workflows
  9. Missions
  10. Knowledge Base
  0. Back
```

Selecting **9. Missions** opens the Missions menu:
1. **List Missions**: View all active and completed missions.
2. **Create Mission**: Link to workflow, select target, service port/proto, and optional initial observation.
3. **Open Mission**: Enter the focused operator cockpit.
4. **Start Mission**: Transition OPEN $\to$ IN_PROGRESS.
5. **Complete Mission**: Transition IN_PROGRESS $\to$ COMPLETED.
6. **Abort Mission**: Transition OPEN/IN_PROGRESS $\to$ ABORTED.
7. **Mission Timeline**: View chronological activity stream.
