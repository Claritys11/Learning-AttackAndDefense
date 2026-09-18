from __future__ import annotations
from typing import Mapping
from .models import KnowledgeArticle

AD_ARTICLES: dict[str, KnowledgeArticle] = {
    "overview": KnowledgeArticle(
        id="overview",
        title="What is Attack & Defense?",
        summary="Core format, objectives, and dynamics of Attack & Defense CTF competitions.",
        category="attack-defense",
        tags=("fundamentals", "rules", "format"),
        content="""# Attack & Defense CTF Overview

Attack & Defense (A&D) is a live, round-based cybersecurity competition where teams run identical vulnerable services on their own designated servers (VMs / containers).

Every team has two simultaneous responsibilities:
1. **Attack**: Discover vulnerabilities in enemy services, exploit them to retrieve flags, and submit those flags to the scoring platform.
2. **Defense**: Analyze their own services, patch discovered security flaws without breaking service functionality, and monitor for unauthorized intrusions.

## Core Rules & Constraints
- **Identical Starting Baseline**: At game start, every team's VM contains the exact same services and vulnerabilities.
- **Round / Tick Cadence**: The competition progresses in rapid ticks (typically 1 to 5 minutes per round).
- **Dynamic Rotating Flags**: Flags change every round. An old flag cannot be submitted in a future round beyond the platform's flag lifetime.
- **Infrastructure Integrity**: Disrupting platform infrastructure, VPN gateways, or scoreboard routers is strictly prohibited. Attacks must focus solely on target services.
""",
    ),
    "scoring": KnowledgeArticle(
        id="scoring",
        title="Scoring Dynamics: Attack, Defense, and SLA",
        summary="How points are awarded, deducted, and calculated across rounds.",
        category="attack-defense",
        tags=("scoring", "sla", "strategy"),
        content="""# Scoring Dynamics: Attack, Defense, and SLA

A&D scoring is evaluated at every tick across three primary metrics:

## 1. Attack Points
- Awarded when a team successfully captures an enemy flag and submits it to the platform within its valid lifetime.
- Fast automated exploitation and prompt flag submission maximize attack yield.

## 2. Defense Points
- Deducted or lost when enemy teams steal and submit flags from your team's service.
- If no enemy steals your flag during a tick, your team preserves defense points.

## 3. SLA (Service Level Agreement) Points
- An automated game engine checker (the "SLA Checker") connects to your service every tick to verify:
  * Port accessibility (service is up and reachable).
  * Functional correctness (legitimate user workflows succeed, e.g. register, login, read note).
  * Flag retrieval capability (the checker can plant or fetch the check token).
- **Critical Insight**: "Patched" does NOT mean "Good Defense" if the patch causes service downtime or functional regression. A non-functional service yields 0 SLA, quickly draining your team's standing.
""",
    ),
    "loop": KnowledgeArticle(
        id="loop",
        title="The Operator Execution Loop",
        summary="The practical step-by-step cycle every A&D operator executes each round.",
        category="attack-defense",
        tags=("workflow", "operator", "playbook"),
        content="""# The Operator Execution Loop

In rapid 1-5 minute rounds, operators must follow a disciplined, repeatable operational cycle:

```text
Observe (Check scoreboard, tick timer, SLA status)
   ↓
Recon (Host discovery, port scanning, network map)
   ↓
Enumerate (Service versions, technologies, endpoints)
   ↓
Identify Attack Surface (Review code, find bugs, isolate endpoints)
   ↓
Exploit (Develop targeted, reliable exploit script)
   ↓
Extract Flag (Retrieve dynamic flag from enemy target)
   ↓
Submit Flag (Submit immediately before tick expires)
   ↓
Patch Own Service (Apply surgical fix to own VM)
   ↓
Verify Service (Ensure service passes SLA & functionality tests)
   ↓
Monitor (Inspect network traffic, tcpdump, logs for enemy exploits)
   ↓
Repeat
```

## Speed vs Discipline
- Do not spend 30 minutes writing an overly complex framework.
- Write minimal, reliable scripts that take a target IP/host and output the flag.
- Always test patches against an SLA check script before committing them to your live service.
""",
    ),
    "recon_enum": KnowledgeArticle(
        id="recon_enum",
        title="Reconnaissance & Service Enumeration",
        summary="Tactics for mapping the competition network and discovering service attack surfaces.",
        category="attack-defense",
        tags=("recon", "nmap", "enumeration"),
        content="""# Reconnaissance & Enumeration

## Host Discovery
In an A&D network (usually provided over WireGuard VPN), enemy hosts typically follow a predictable IP pattern:
- Subnet per team: e.g., `10.<team_id>.1.0/24` or `172.x.x.<team_id>`.
- Use fast host discovery (`nmap -sn`) across the designated competition CIDR.

## Port & Service Scanning
- Avoid noisy, slow full scans during ticks. Target the known service port range.
- Service detection (`nmap -sV -sC -p <ports> <host>`) determines:
  * Application framework (Python Flask, Node.js, PHP, Go, C binary).
  * Underlying web server and database.
- Directory and endpoint fuzzing (`ffuf -u http://<target>:<port>/FUZZ -w wordlist.txt`) reveals hidden endpoints or API routes.
""",
    ),
    "defense_patching": KnowledgeArticle(
        id="defense_patching",
        title="Defensive Patching & SLA Protection",
        summary="Surgical remediation, rollback strategy, and preserving service availability.",
        category="attack-defense",
        tags=("defense", "patching", "sla", "incident-response"),
        content="""# Defensive Patching & SLA Protection

## Golden Rule of Defense
**Never break legitimate functionality to block an attack.**

If you delete the service or block all POST requests with an iptables firewall:
- You may prevent attackers from reading `/flag`.
- But the SLA checker will fail immediately, costing your team massive SLA penalties every tick.

## Patching Tactics
1. **Source Code Review**: Inspect the challenge source code on your own VM (accessed via SSH).
2. **Surgical Fixes**:
   - For SQL Injection: Use parameterized queries instead of string concatenation.
   - For Command Injection: Remove shell invocation, validate input regex, use `shlex.quote` or fixed argument lists.
   - For Path Traversal: Resolve canonical path and verify prefix against allowed storage directory.
   - For Binary Exploits: Fix buffer sizes, patch format strings, or add bounds checks in disassembly/source.
3. **Backup Before Edit**:
   - Always copy the original service binary/file to a backup path (e.g. `service.py.bak`).
4. **Verification**:
   - Test that normal user actions still work.
   - Run the exploit against your patched service to verify the fix works.
   - Restart the service cleanly via `systemctl restart <unit>` or docker restart.
""",
    ),
    "traffic_monitoring": KnowledgeArticle(
        id="traffic_monitoring",
        title="Traffic Monitoring & Incident Response",
        summary="Using tcpdump and socket tools for traffic analysis, attack observation, and defensive remediation.",
        category="attack-defense",
        tags=("monitoring", "tcpdump", "incident-response"),
        content="""# Traffic Monitoring & Incident Response

## Watching the Wire
While your team is operating, enemy teams will target your services. Your own network traffic is an invaluable telemetry source:
- Run bounded packet captures (`tcpdump -i <interface> -n -w /tmp/capture.pcap 'tcp port <service_port>'`).
- Filter for incoming HTTP requests or payloads targeting known service ports.
- When an exploit attempt is observed against your service, reconstruct the request structure and input parameters.
- Use these observations to:
  1. Understand the attacker's methodology and identify the vulnerable code path.
  2. Develop and apply a surgical defensive patch.
  3. Verify that the patched service resists the observed attack pattern while preserving SLA.

## System Socket Monitoring
- Check listening ports and active inbound connections using `ss -tulpn` or `ss -tan`.
- Identify unexpected persistent connections or listening sockets.
""",

    ),
}

def get_ad_article(article_id: str) -> KnowledgeArticle | None:
    return AD_ARTICLES.get(article_id)

def list_ad_articles() -> tuple[KnowledgeArticle, ...]:
    return tuple(AD_ARTICLES.values())
