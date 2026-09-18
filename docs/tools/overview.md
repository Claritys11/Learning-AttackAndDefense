# Tools Layer Architecture & Overview

The ATTNNDEF tooling layer provides structured, safe, subprocess-based tool execution for operators during Attack & Defense competitions.

## Layered Architecture

```text
Operator Console / Direct CLI
              ↓
         Tool Service
              ↓
         Tool Adapter
              ↓
          ToolRunner
              ↓
   External Process / Subprocess
```

## Safety & Process Isolation Guarantees

1. **No `shell=True`**: All commands are constructed as structured argument vectors (`tuple[str, ...]`). Arbitrary user input is never formatted into a shell string.
2. **Strict Timeouts & POSIX Process Groups**: Every tool invocation has a bounded timeout. On POSIX systems, `ToolRunner` launches processes in a new session (`start_new_session=True`) and terminates the entire process group (`os.killpg`) upon timeout, preventing orphaned background processes.
3. **Structured Results**:
   Every execution produces a normalized `ToolResult`:
   - `command`: Argument vector executed.
   - `returncode`: Exit status code.
   - `stdout` & `stderr`: Captured text outputs.
   - `duration_s`: Execution elapsed time in seconds.
   - `timed_out`: Boolean indicating whether bounded timeout was exceeded.
   - `error_kind`: Normalized category (`success`, `timeout`, `not_found`, `permission`, `nonzero_exit`, `os_error`).

## Tool Catalog

- **Nmap** (`nmap.py`): Host discovery, port scanning, service version enumeration with structured XML parsing.
- **HTTP / Curl** (`http.py`): GET/POST requests, custom headers, request payload inspection, status code and header parsing.
- **ffuf** (`ffuf.py`): Web endpoint and directory discovery with JSON match record parsing.
- **SSH** (`ssh.py`): Non-interactive command execution on authorized competition VMs via key-based authentication.
- **tcpdump** (`tcpdump.py`): Bounded network traffic capture, packet filtering (BPF), and payload inspection.
- **GDB** (`gdb.py`): Local binary inspection, crash backtrace, and register debugging.
- **Linux System Tools** (`system.py`): Quick diagnostics for `ss`, `ps`, `systemctl`, `ip`, `dig`, and `wireguard`.
