# ATTNNDEF Architecture Document

## Product Vision

ATTNNDEF is a local-first **Attack & Defense operator console + knowledge base**. It provides practical security tools, Attack & Defense knowledge, and GZCTF-specific operational information in a terminal-oriented interface.

```text
┌─────────────────────────────────────────────────────────────┐
│                       OPERATOR CONSOLE                      │
│                                                             │
│  1. Targets         2. Tools           3. Attack & Defense  │
│  4. GZCTF           5. Competition     6. Settings          │
└──────────────┬──────────────┬───────────────────────────────┘
               │              │
               ▼              ▼
     ┌──────────────────┐   ┌────────────────────────┐
     │ TARGET           │   │ TOOL LAYER             │
     │ INTELLIGENCE     │   │                        │
     │ - Target Service │   │ - ToolRunner (safe)    │
     │ - History & Diffs│   │ - Adapters & Services: │
     │ - Scope Guard    │   │   Nmap, HTTP, ffuf,    │
     │ - Observations   │   │   SSH, tcpdump, GDB,   │
     │                  │   │   Linux System (ss/ps) │
     └──────────────────┘   └────────────────────────┘
               ▲
               │ Context & Knowledge
     ┌─────────┴────────┐
     │ KNOWLEDGE BASE   │
     │ - A&D Workflow   │
     │ - SLA & Defense  │
     │ - GZCTF Guide    │
     └──────────────────┘
```

## Layered Tooling Architecture

Tools follow strict dependency injection:
```text
Interactive UI / CLI Command
             ↓
        ToolService
             ↓
        ToolAdapter
             ↓
         ToolRunner
             ↓
      Subprocess execution
```

### Safety Rules:
1. **No `shell=True`**: All subprocess invocations use explicit argument lists.
2. **Process Group Termination**: On POSIX, `os.killpg` ensures sub-processes terminate cleanly on timeout.
3. **Structured Results**: Every execution produces a `ToolResult` with normalized `error_kind` and timing metrics.
4. **Offline Testability**: All adapters work with `FakeToolRunner` using mock outputs and fixtures.

## Target Intelligence

Tool outputs feed into `Observation` records. The intelligence engine performs structured diffing across observation snapshots:
- Port/service state changes (new port opened, port closed)
- Version changes (e.g. Apache/nginx patched)
- Host status transitions (up/down)

## Knowledge & Platform Isolation

Operational knowledge and platform guidelines (such as GZCTF) remain cleanly decoupled from tool execution logic. Core concepts remain platform-agnostic, while platform adapters provide platform-specific context.
