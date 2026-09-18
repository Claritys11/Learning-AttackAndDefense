# Tool Learning Matrix

These are learning tools, separate from the repository's `attnndef` automation.

| Area | Tool | Practice |
|---|---|---|
| Recon | `nmap` | authorized lab service discovery |
| Web | `curl` | manual requests and response analysis |
| Web | Burp/ZAP | request manipulation in lab |
| Web | `ffuf` | scoped content discovery |
| DNS | `dig` | DNS records and resolution |
| Network | `ss` | local listeners and owning process |
| Network | `tcpdump`/Wireshark | packet observation in lab |
| Binary | `gdb`/pwndbg | debug local binaries |
| Binary | `checksec`/`readelf`/`objdump` | inspect mitigations and symbols |
| Binary | `pwntools` | write bounded local PoCs |
| Linux | `strace` | syscall observation |
| Linux | `lsof` | process/file/socket mapping |
| Linux | `journalctl` | event review |
| Source | `rg` | find dangerous sinks and auth checks |
| Automation | Python/Bash/jq | repeatable evidence and workflows |

For every tool, learn: what it does, why it matters in A&D, safe scope, one basic command, one lab task, and one common mistake. Start with manual tools; use `attnndef` only after you understand the observation being automated.
