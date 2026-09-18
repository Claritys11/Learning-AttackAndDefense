# Attack & Defense Operational Core

The **Operational Core** provides structured state tracking and workflow logging for an Attack & Defense competition session.

---

## 1. Architectural Distinction

A foundational boundary exists between **Target Intelligence** and the **Operational Core**:

> **Target Intelligence describes what the environment looks like.**
> **Operational Core records what the operator did about it.**

```text
┌─────────────────────────────────────────────────────────────┐
│                    TARGET INTELLIGENCE                      │
│                                                             │
│  - Targets, Hosts, Roles (OWN, ENEMY, INFRASTRUCTURE)       │
│  - Port & Service Observations (XML, Service versions)      │
│  - Intelligence Diffs (added/removed/changed services)      │
│  - Scope Enforcement & Execution Boundaries                 │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               │ observation context
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                      OPERATIONAL CORE                       │
│                                                             │
│  - Competition Session (local profile & context)            │
│  - Round & Tick State (local operator tracking)             │
│  - Operator Actions (RECON, ATTACK, DEFENSE, FLAG, VERIF)   │
│  - Attack Records (targets, methods, execution status)      │
│  - Defense Records (targets, remediation, patches)          │
│  - Flag Lifecycle (SHA-256 fingerprints, masked previews)   │
│  - SLA Observations (local latency & health observations)   │
│  - Unified Chronological Activity Timeline                  │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Local Tracking vs Remote State

ATTNNDEF currently performs **local operator tracking**, NOT remote platform synchronization:

* **Local Round Tracking**: When an operator advances or sets a round (e.g. `Round #3`), ATTNNDEF records that the operator is working within Round 3. It does **not** imply that ATTNNDEF commanded or synchronized with the remote competition engine.
* **No Remote GZCTF API Calls**: ATTNNDEF makes zero autonomous HTTP or WebSocket calls to GZCTF endpoints.
* **Operator Responsibility**: The human operator remains in full control of decisions, tool launches, patch applications, and external flag submissions.

---

## 3. Data Models & Lifecycle

### A. Session & Round Model
* **`Session`**: Tracks the competition name, platform hostname (`jjz.jatimprov.go.id`), team ID, operator name, VPN interface (`wg0`), and assigned subnet ranges.
* **`Round`**: Local tracking of round number, start timestamp, end timestamp, and status (`ACTIVE`, `ENDED`).
* **`Tick`**: Fine-grained local observations within a round.

### B. Operator Actions (`OperatorAction`)
Explicitly logs actions performed by the operator across six core categories:
1. `RECON`: Host sweeps, port scans, directory discovery.
2. `ATTACK`: Manual exploit attempts, payload tests, scripted executions.
3. `DEFENSE`: Service configuration updates, WAF rules, firewall adjustments.
4. `FLAG`: Identification and recovery of dynamic flags.
5. `VERIFICATION`: Post-patch functionality testing, smoke tests, health probes.
6. `SYSTEM`: Diagnostic inspection (`ss`, `ps`, `systemctl`, `wg show`).

### C. Attack & Defense Records
* **`AttackRecord`**: Tracks targeted services, chosen attack vectors/methods, execution status (`PLANNED`, `IN_PROGRESS`, `SUCCESS`, `FAILED`, `ABORTED`), and operator notes.
* **`DefenseRecord`**: Tracks defensive interventions (`configuration change`, `service restart`, `input validation fix`, `access-control change`), remediation status, and verification notes.

### D. Flag Security & Fingerprints
To prevent accidental leakage or persistent exposure of competition secrets:
* **No Plaintext Flag Persistence**: Raw flags entered or captured are immediately digested into SHA-256 hashes (`fingerprint = sha256:<hash>`).
* **Masked Previews**: Previews are stored as redacted substrings (e.g. `flag{...1a2b}`).
* **Status Lifecycle**: `OBSERVED` → `VALIDATED` → `SUBMITTED` (recorded as submitted externally by operator) → `REJECTED` / `EXPIRED`.

### E. SLA Observations
* Records local responsiveness (`status = OK | MUMBLE | OFFLINE`, `latency_ms`).
* Explicitly distinguishes `source = local` from official platform scoring.

---

## 4. Unified Activity Timeline

The Operational Core aggregates all actions, attacks, defenses, flags, and SLA observations into a deterministic, chronological timeline:

```text
20:31:02  RECON         enemy-web-01  Nmap port scan
20:31:18  ATTACK        enemy-web-01  HTTP request (/api/vuln)  SUCCESS
20:31:41  FLAG          enemy-web-01  flag{...1a2b} via HTTP    VALIDATED
20:32:05  DEFENSE       own-web-01    nginx config hardening    COMPLETED
20:32:21  SLA           own-web-01    http/80 (local) 42ms      OK
```

This chronological stream gives the operator complete situational awareness during rapid competition rounds.
