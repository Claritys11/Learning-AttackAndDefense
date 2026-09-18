# The Attack & Defense Operator Workflow

## The Core Loop

```text
Observe  ───►  Recon  ───►  Enumerate  ───►  Identify Surface
   ▲                                                 │
   │                                                 ▼
Repeat  ◄───  Monitor ◄───  Verify  ◄───  Patch ◄─── Exploit / Extract / Submit
```

### 1. Observe
- Review current round number, tick countdown, SLA status, and recent points on scoreboard.
- Identify which services have been targeted or are failing health checks.

### 2. Reconnaissance
- Discover active enemy IPs across the competition WireGuard subnet.
- Map open ports and verify reachability.

### 3. Enumeration
- Profile the application stack (web frameworks, binary services, databases).
- Identify endpoints, parameters, and input handlers.

### 4. Vulnerability Identification
- Review service source code from your team VM.
- Search for common flaw patterns: SQL injection, command execution, path traversal, broken auth, memory corruption.

### 5. Exploitation & Flag Retrieval
- Develop a concise, deterministic script that sends the payload to an enemy target and retrieves the live flag.
- Execute across reachable enemy targets within the round.

### 6. Immediate Flag Submission
- Submit captured flags to the submission endpoint before the tick expires.
- Remember: Stolen flags have a strict expiration window.

### 7. Defense & Patching
- Apply a minimal, surgical fix to your team VM.
- Do not disable endpoints or shut down ports; preserve legitimate service functionality.

### 8. Verification & SLA Testing
- Run functional checks against the patched service to verify the exploit fails AND legitimate workflows succeed.
- Verify SLA checker passes.

### 9. Traffic Monitoring
- Monitor incoming traffic using `tcpdump` to detect enemy exploit attempts, analyze their payloads, and counter-attack unpatched teams.
