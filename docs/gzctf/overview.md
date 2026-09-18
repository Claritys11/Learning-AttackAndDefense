# GZCTF Platform Overview & Architecture

## Background
GZCTF is an open-source CTF platform developed originally for Jeopardy CTF, with extended support for **Attack & Defense** (`ChallengeType: AttackDefense`).

## Primary Architectural Concepts (Based on GZCTF Source & Docs)

### 1. Rounds & Ticks
- Games run on an event-wide tick window configured by `Game.AdTickSeconds` (typically 60 to 300 seconds).
- The game begins with an optional warmup window (`Game.AdWarmupSeconds`, default 30 minutes) to allow WireGuard VPN connection and network verification. No SLA checks or flags run during warmup.
- `AdRoundScheduler` polls every 5 seconds and calls `AdRoundService.AdvanceAsync` atomically when a round expires.

### 2. Containers and Networking
- Every team receives an isolated container instance per challenge (`AdContainerManager`, reconciled every 15s).
- Network isolation options:
  * **Open Bridge** (`ad.allowEgress: true`): Boxes have filtered outbound internet access and talk to other teams via WireGuard.
  * **Isolated Bridge** (`ad.allowEgress: false`): Outbound egress denied; boxes only communicate over the WireGuard VPN.

### 3. Dynamic Flag Mechanics
- Format: `flag{<24 random url-safe-base64 bytes>}`.
- Location specified via the **`GZCTF_FLAG_FILE`** environment variable:
  * In Docker: `/flag` via host read-only bind mount (`:ro`).
  * In Kubernetes: `/gzctf-flag/flag` via pull sidecar.
- There is **no static `GZCTF_FLAG` env var** inside the service box because environment variables are frozen at container startup.
- Flags expire after `Game.AdFlagLifetimeTicks` rounds (default 5).

### 4. SLA Checker Service
- `AdCheckerService` runs on a 10s cadence independently from the round advance scheduler.
- Evaluates accessibility, functional contracts, and check tokens.
- Exit code 0 indicates healthy service; non-zero indicates SLA failure.
