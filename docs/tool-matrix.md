# Tool Matrix

Use these only against localhost, a declared fixture, or a target you explicitly own.

| Tool | Skill | When in a round | First command | Output to record | Lab |
|---|---|---|---|---|---|
| `nmap` | Enumeration | Initial mapping of an authorized host | `nmap -sV --top-ports 100 HOST` | ports/services | 01 |
| `curl` | HTTP analysis | After finding a web service | `curl -i http://HOST:PORT/health` | status/headers/body | 01–04 |
| `ffuf` | Content discovery | Routes are unknown | scoped wordlist against localhost | discovered paths/status | web labs |
| `ss` | Defense enumeration | Check own listeners | `ss -lntup` | listener/process | 01 |
| `lsof` | Process mapping | Correlate socket to process | `lsof -iTCP -sTCP:LISTEN` | owning process | 01 |
| `rg` | Source review | Source/config is available | `rg 'system|exec|subprocess|eval' .` | candidate sinks | 02–04 |
| `strace` | Runtime observation | Validate process behavior locally | `strace -f ...` | relevant syscalls | 02 |
| `journalctl` | Event monitoring | Review service events | `journalctl -u SERVICE` | timestamp/actor/event | monitoring |
| `gdb` | Binary analysis | Local pwn lab | `gdb ./challenge` | control flow/regs | pwn |
| `checksec` | Mitigation review | Before binary exploit work | `checksec --file=./challenge` | enabled mitigations | pwn |
| `tcpdump` | Traffic analysis | Need protocol evidence | `tcpdump -i lo -nn PORT PORT` | packets/timing | network |
| `jq` | Evidence handling | Inspect structured output | `jq . evidence.json` | redacted fields | all |

For each tool, learn: what, why, scope, first command, output, common mistake, and lab mapping. `attnndef` automates repeatable workflow only after manual observation is understood.
