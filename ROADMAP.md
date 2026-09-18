# Learning A&D Roadmap

This is the main learning entry point. The repository teaches a repeatable loop:

```text
concept -> observe -> reproduce -> attack -> defend -> verify
```

The automation engine is secondary. Build manual understanding first, then use `attnndef` to make the workflow repeatable.

## Progression

| Phase | Focus | Output |
|---|---|---|
| 0 | Linux, networking, SSH, VPN concepts | Admin and network baseline |
| 1 | Enumeration and asset mapping | Service/endpoint inventory |
| 2 | Source review and threat modeling | Data-flow and root-cause notes |
| 3 | Web vulnerabilities | Reproducible local PoCs |
| 4 | Binary/protocol fundamentals | Debugging and state-machine skills |
| 5 | Authentication and authorization | Auth matrix and abuse cases |
| 6 | Privilege escalation | Misconfiguration-to-impact reports |
| 7 | Defense and hardening | Minimal patches preserving SLA |
| 8 | Monitoring and detection | Structured security events |
| 9 | Patching, replay, rollback | Exploit-closed regression proof |
| 10 | A&D operations | Bounded attack/defense waves |
| 11 | Timed mock competition | Complete local simulation |

## Weekly study loop

For each topic:

1. Read the linked learning note.
2. Run the lab in guided mode.
3. Repeat with hints only when blocked.
4. Repeat without hints and record time.
5. Patch the root cause.
6. Run health, replay, regression, and rollback.
7. Update `PROGRESS.md`.

## Mastery levels

- L1 — explain the concept and recognize the pattern.
- L2 — reproduce it with guidance.
- L3 — solve and patch it without guidance.
- L4 — solve, defend, monitor, and explain it under a time limit.

## Priority tiers

### Tier A — core final-LKS skills

Linux, networking, enumeration, source review, web, authentication, privilege escalation, patching, SLA, monitoring.

### Tier B — important extensions

Pwn, binary protocols, CVE reproduction, Docker/container security, forensics.

### Tier C — operations

Automation, target registries, flag extraction, concurrency, evidence, submission adapters.

### Tier D — situational platform skills

Active Directory depth, OAuth edge cases, honeypots, anti-cheat, egress analysis.

## Learning notes

- [Linux and administration](docs/learning/linux.md)
- [Networking and access](docs/learning/networking.md)
- [Enumeration](docs/learning/enumeration.md)
- [Source review](docs/learning/source-review.md)
- [Web attack/defense](docs/learning/web.md)
- [Authentication](docs/learning/authentication.md)
- [Privilege escalation](docs/learning/privesc.md)
- [Defense and SLA](docs/learning/defense.md)
- [Monitoring](docs/learning/monitoring.md)
- [A&D operations](docs/learning/ad-operations.md)

## Labs

Start with the five core labs:

- [01 Enumeration](labs/01-enumeration/README.md)
- [02 Command Injection](labs/02-command-injection/README.md)
- [03 Path Traversal](labs/03-path-traversal/README.md)
- [04 Authentication Bypass](labs/04-auth-bypass/README.md)
- [05 Mini A&D](labs/05-mini-ad/README.md)

Then add labs for SQLi, SSTI, JWT, deserialization, buffer overflow, ret2libc, Linux/Windows privilege escalation, and monitoring.

## No-AI mode

Use the lab checklist without consulting solutions or AI. A complete result requires attack proof, root-cause explanation, patch, SLA proof, exploit replay failure, and rollback—not just a captured flag.

See `docs/quickstart.md`, `docs/tools-guide.md`, and `docs/competition-runbook.md` for commands and competition operations.