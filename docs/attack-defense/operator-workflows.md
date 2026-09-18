# Operator Workflows & Evidence Correlation

The **Operator Workflow & Evidence Correlation** subsystem provides an operator-controlled grouping mechanism to link reconnaissance, attack actions, defensive remediation, verification checks, and evidence into a structured narrative.

---

## 1. What is an Operator Workflow?

An **Operator Workflow** (`WorkflowRun`) is a lightweight, local-first container for grouping related actions, observations, and evidence collected during an Attack & Defense competition session.

A workflow represents a coherent operator activity, for example:
* Investigating an unexpected HTTP service on a compromised host.
* Executing a reconnaissance scan, inspecting vulnerability evidence, and recording an attack attempt.
* Deploying a service configuration patch and verifying health/SLA status afterward.

### Core Workflow Model
```text
WorkflowRun
├── workflow_id    : Unique identifier (UUID)
├── session_id     : Associated competition session
├── round_id       : Round during which workflow started
├── title          : Operator-assigned title
├── objective      : Stated objective or hypothesis
├── target_id      : Optional target host/service reference
├── started_at     : UTC timestamp when workflow began
├── completed_at   : Optional completion/abortion timestamp
├── status         : ACTIVE | COMPLETED | ABORTED
└── notes          : Operator notes or post-mortem summary
```

---

## 2. What a Workflow is NOT (Explicit Non-Goals)

To preserve operator control and security boundaries:

* **NOT an Autonomous Attack Engine**: Workflows do NOT automatically plan, chain, or execute exploits.
* **NOT an Automated Flag Stealer / Submitter**: Workflows do NOT intercept flags or send API requests to remote game servers.
* **NOT an Authorization Bypass**: Associating a target with a workflow (`target_id = "target-03"`) does **NOT** grant authorization to attack it. Network commands still strictly pass through `ExecutionBoundary` and `Scope`.
* **NOT a Proof of Remote Competition Success**: Marking a workflow as `COMPLETED` records an operator's local completion of their task. It does **not** query remote GZCTF servers to verify points or score submission.
* **NOT an Automatic Patching Agent**: Workflows do not autonomously modify remote files or patch binaries without operator intervention.

---

## 3. Relationship to Operational Records

Workflows connect existing domain entities without duplicating persistence or requiring mandatory workflow membership:

```text
                        ┌──────────────────────────────┐
                        │         WorkflowRun          │
                        │ (status: ACTIVE | COMPLETED) │
                        └──────────────┬───────────────┘
                                       │ 1:N optional foreign key
         ┌─────────────────────────────┼──────────────────────────────┬──────────────────────────────┐
         ▼                             ▼                              ▼                              ▼
┌──────────────────┐          ┌──────────────────┐           ┌──────────────────┐          ┌──────────────────┐
│  OperatorAction  │          │   AttackRecord   │           │  DefenseRecord   │          │  SlaObservation  │
│ - recon          │          │ - method         │           │ - patch/mitigate │          │ - latency / ping │
│ - verification   │          │ - status         │           │ - status         │          │ - health status  │
│ - parent_action  │          └──────────────────┘           └──────────────────┘          └──────────────────┘
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  EvidenceRecord  │
│ - evidence_id    │
│ - tool_exec_id   │
│ - stdout preview │
└──────────────────┘
```

* **Optional Reference (`workflow_id`)**: All operational records (`OperatorAction`, `AttackRecord`, `DefenseRecord`, `FlagRecord`, `SlaObservation`) support an optional `workflow_id`. Records created outside any workflow remain fully valid.
* **Cross-Session Consistency**: A record can only be attached to a workflow belonging to the same competition session.
* **Referential Integrity**: SQLite foreign keys maintain consistency with session, round, and target tables.

---

## 4. Evidence & Tool Execution Correlation

Operational actions can directly reference concrete artifacts produced by tool runs:

1. **Tool Execution Record (`ToolExecutionRecord`)**:
   - Every external tool invocation executed through `ToolRunner` receives a unique, stable `tool_execution_id` (e.g. `texec_01J...`).
   - Captures command vectors, exit codes, execution duration, and truncated output previews without logging raw sensitive credentials or flags.
2. **Evidence Record (`EvidenceRecord`)**:
   - Stores evidentiary artifacts on disk (`evidence/`) with SHA-256 integrity hashes.
3. **Correlation in OperatorAction**:
   - An `OperatorAction` can reference both `evidence_id` and `tool_execution_id`.
   - This provides bidirectional traceability:
     $$\text{Tool Execution} \longrightarrow \text{Evidence Artifact} \longrightarrow \text{Operator Action} \longrightarrow \text{Workflow Timeline}$$

---

## 5. Target Intelligence Boundary

Workflows integrate with **Target Intelligence** without mutating domain boundaries:

* **Read-Only Context**: When a workflow is scoped to a target (`target_id`), the operator can inspect target metadata, host role (`OWN`, `ENEMY`, `INFRASTRUCTURE`), discovered services, and historical observations.
* **Scans Flow Through Existing Pipelines**: A workflow does not perform scans itself. Scans must be initiated through `Scope` $\rightarrow$ `ReconService` $\rightarrow$ `NmapAdapter` $\rightarrow$ `Observation` $\rightarrow$ `IntelligenceDiff`.
* **Intelligence Isolation**: Starting or completing a workflow does not alter target intelligence state.

---

## 6. Verification Workflows & Causality

A critical phase in Attack & Defense is post-action verification (e.g., verifying that a patch did not break the service SLA, or confirming that an exploit succeeded).

### Explicit Linkage via `parent_action_id`
ATTNNDEF does **not** infer causality automatically. It does not assume that exit code 0 on a health check means a defense was successful.

Instead, the operator explicitly records verification:
1. Operator records a defense action:
   ```text
   Action #act-1 (DEFENSE): Restart service with hardened config
   ```
2. Operator performs a verification check (e.g., `curl /health` or SLA probe) and records:
   ```text
   Action #act-2 (VERIFICATION): HTTP health check returned 200 OK
   parent_action_id: act-1
   ```

Both facts are recorded distinctly and linked deterministically in the timeline.

---

## 7. Local vs Remote State

| Concept | Local State (ATTNNDEF) | Remote State (Competition Platform / GZCTF) |
|---|---|---|
| **Round** | Active local working round | Official server round clock & state |
| **Workflow** | Operator task container & notes | None (workflows are purely internal to the team) |
| **Attack Record** | Log of operator-launched attack attempt | Scoring server flag capture validation |
| **Defense Record** | Local mitigation / patch log | Defense point deductions / SLA checking |
| **Flag Fingerprint** | Local SHA-256 fingerprint + masked preview | Server flag submission accepted/rejected |
| **SLA Observation** | Local latency / health check observation | Official gameserver check result |

---

## 8. CLI Usage

### Managing Workflows
```bash
# Create a new workflow
attnndef workflow --create --title "Investigate Web Port 8080" --objective "Check directory traversal vulnerability" --target target-03

# List workflows
attnndef workflow --list
attnndef workflow --list --status ACTIVE

# Inspect a workflow
attnndef workflow --show <workflow_id>

# View workflow timeline
attnndef workflow --timeline <workflow_id>

# Complete or abort a workflow
attnndef workflow --complete <workflow_id> --notes "Vulnerability confirmed patched and verified"
attnndef workflow --abort <workflow_id> --notes "Service unreachable; pivot to target-04"
```

### Associating Records with Workflows
```bash
# Record an action inside a workflow
attnndef action --type verification --description "HTTP health check" --workflow <workflow_id> --parent <parent_action_id>

# Record an attack inside a workflow
attnndef attack --target target-03 --service web --method "cve-2023-xxxx" --status executed --workflow <workflow_id>

# Record a defense inside a workflow
attnndef defense --target target-01 --service web --mitigation "filter bad characters in input" --status verified --workflow <workflow_id>

# Record a flag capture inside a workflow
attnndef flag --flag "flag{sample_flag_1234}" --direction captured --target target-03 --service web --workflow <workflow_id>

# Query timeline filtered by workflow
attnndef timeline --workflow <workflow_id>
```

All commands support `--json` for machine readability and scripting.
