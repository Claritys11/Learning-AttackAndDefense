# ATTNNDEF — Attack & Defense Operator Toolkit & Knowledge Base

`ATTNNDEF` is a local-first **Attack & Defense operator console + knowledge base** designed for CTF competitions (such as Grand Final A&D on GZCTF / `jjz.jatimprov.go.id`).

The project answers the three essential operator questions during competition:
```text
"What tool should I use?"
"What does this A&D concept mean?"
"How does the competition/platform work?"
```

```text
┌─────────────────────────────────────────────────────────────┐
│                  ATTACK & DEFENSE TOOLKIT                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. TOOLS                                                   │
│     Practical tools used during A&D: Nmap, HTTP, ffuf,     │
│     SSH, tcpdump, GDB, and Linux system diagnostics         │
│                                                             │
│  2. A&D KNOWLEDGE                                           │
│     Concepts, workflow, scoring, SLA, tactics, loop         │
│                                                             │
│  3. GZCTF                                                   │
│     Platform architecture, flag mechanics, SLA checker,     │
│     WireGuard VPN, and competition operations               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

> **Note**: This repository is **NOT** a vulnerable lab platform, learning-lab framework, or autonomous hacking agent. It provides structured command execution, operational intelligence, and reference knowledge for human operators.

---

## 1. The Three Core Pillars

### A. Practical Operator Tools
Structured, safe subprocess-based execution (`ToolRunner`) with no `shell=True`, bounded timeouts, and POSIX process group cleanup (`killpg`):
* **Nmap**: Host discovery (`-sn`), port scanning (`-p`), and service detection (`-sV -sC`) with structured XML parsing.
* **HTTP / Curl**: GET and POST request inspection, custom headers, payload bodies, and HTTP status/header parsing.
* **ffuf**: Directory and endpoint fuzzing with structured JSON match parsing.
* **SSH**: Non-interactive command execution on authorized competition VMs using SSH keys (`-i <key>`).
* **tcpdump**: Bounded packet captures, BPF filtering, and traffic inspection for detecting enemy exploit payloads.
* **GDB**: Minimal batch inspection (`--batch -ex`) for binary analysis, crash dumps, registers, and backtraces.
* **System Diagnostics**: Lightweight tools for `ss` (sockets), `ps` (processes), `systemctl` (services), `ip` (addresses/routes), `dig` (DNS), and `wg` (WireGuard status).

### B. Attack & Defense Operational Knowledge
Practical, competition-tested concepts:
* **The Operator Execution Loop**: Observe → Recon → Enumerate → Surface → Exploit → Extract → Submit → Patch → Verify → Monitor → Repeat.
* **Scoring Dynamics**: Attack points, Defense deductions, and SLA availability.
* **SLA & Availability**: Why "Patched" does not equal "Good Defense" if a patch breaks legitimate functionality or causes service downtime.
* **Defensive Patching**: Surgical remediation, backup strategies, and smoke testing.
* **Traffic Monitoring**: Reconstructing enemy payloads from incoming network packets to develop instant patches and counter-attacks.

### C. GZCTF Platform Operations
Derived directly from primary GZCTF documentation and source:
* **Round & Tick Cadence**: `AdWarmupSeconds` (warmup period without flags/SLA), `AdTickSeconds` (1-5 min rounds), atomic advance transactions.
* **Container Lifecycle & Networks**: Per-team challenge containers, `Open` bridge vs `Isolated` bridge (`ad.allowEgress`).
* **Dynamic Flag Delivery**: `flag{...}` rotating flags delivered via `GZCTF_FLAG_FILE` (`/flag` in Docker via read-only host bind mount; `/gzctf-flag/flag` in Kubernetes).
* **Flag Expiration**: `AdFlagLifetimeTicks` (flags expire after 3-5 rounds).
* **SLA Checker**: Independent 10-second cadence, functional verification contracts, exit code semantics (0=pass, 1=fail).
* **Competition Setup**: WireGuard VPN connection (`wg0`), SSH key authentication, and tournament rules (e.g. `jjz.jatimprov.go.id`).

---

## 2. Architecture

```text
Operator Console / Direct CLI
             ↓
        Tool Service
             ↓
        Tool Adapter
             ↓
         ToolRunner
             ↓
      Subprocess execution
```

### Safety & Reliability Guarantees
1. **No `shell=True`**: All commands are constructed as lists of arguments.
2. **Strict Timeouts**: POSIX process group termination ensures zero dangling child processes.
3. **Structured Results**: Every run produces normalized outputs (`success`, `timeout`, `not_found`, `permission`, `nonzero_exit`).
4. **Offline Testable**: Complete test suite runs offline without internet, real VMs, or live platforms.

---

## 3. Quickstart

### Installation

```bash
git clone https://github.com/Claritys11/Learning-AttackAndDefense.git
cd Learning-AttackAndDefense
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m pip install pytest
```

### Running the Operator Console

```bash
attnndef
```

The interactive menu provides quick access to:
```text
ATTNNDEF
────────────────────────────
  1. Targets
  2. Tools
  3. Attack & Defense
  4. GZCTF
  5. Competition
  6. Settings
  0. Exit
```

### Running the Test Suite

```bash
.venv/bin/pytest -v
```

---

## 4. Documentation Index

- [`docs/architecture.md`](docs/architecture.md): Overall system design and safety boundaries.
- **Tools**:
  - [`docs/tools/overview.md`](docs/tools/overview.md): Tool layer architecture and adapters.
- **Attack & Defense**:
  - [`docs/attack-defense/overview.md`](docs/attack-defense/overview.md): Match format and dynamics.
  - [`docs/attack-defense/workflow.md`](docs/attack-defense/workflow.md): The operator execution loop.
  - [`docs/attack-defense/sla.md`](docs/attack-defense/sla.md): SLA preservation and defensive patching.
- **GZCTF**:
  - [`docs/gzctf/overview.md`](docs/gzctf/overview.md): Platform architecture and flag mechanics.
  - [`docs/gzctf/competition.md`](docs/gzctf/competition.md): Operational guide for GZCTF competitions (VPN, SSH, rules).

---

## 5. Scope Boundaries

This project strictly adheres to operator-assist boundaries:
- ❌ No autonomous hacking agents.
- ❌ No automatic exploit generation or blind mass exploitation.
- ❌ No platform infrastructure denial-of-service.
- ❌ No learning-lab fixtures or educational progression systems.
- ✅ Practical operator tools.
- ✅ Safe subprocess execution.
- ✅ Structured operational knowledge.
- ✅ Platform-accurate GZCTF reference.
