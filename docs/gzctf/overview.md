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

### 4. SLA Checker Service & Exit Codes
- `AdCheckerService` runs on a 10s cadence (`MaxCheckAttempts = 3`, `RetryDelay = 1.5s`) independently from the round advance scheduler.
- Evaluates accessibility, functional contracts, and check tokens.
- **Exit Code Mapping (`AdCheckMapping`)**:
  * **Custom Checker (enochecker3 standard)**:
    - Exit `0`: `Ok` (passes health check, full SLA credit).
    - Exit `1`: `Mumble` (service reachable but returned invalid/corrupted data).
    - Exit `2`: `Offline` (connection refused, timed out, or process down).
    - Exit `3+`: `InternalError` (checker error/infra fault, earns 0 but does not drag down score).
  * **Built-in TCP Probe**:
    - Exit `0`: `Ok`.
    - Any non-zero: `Offline`.

### 5. Scoring Math (`AdScoring.cs`)
- Net score: `Total = Attack + SLA - DefenseLoss`
- **Attack Points**: `Σ (AttackPool / k)` where `k` is the count of teams that stole the flag (`AttackPool = 1.0`). Rewards exclusive exploitation.
- **Defense Loss**: `DefensePool * compromisedFlags` (`DefensePool = 1.0`). Deducted once per distinct compromised flag.
- **SLA Points**: `Σ (TickCredit * SlaFieldFactor)` where:
  * `TickCredit`: `1.0` (clean Ok), `0.5` (recovering after Offline/Mumble), `0.0` (Offline, Mumble, or InternalError).
  * `SlaFieldFactor`: `sqrt(max(1, activeTeams))`.
