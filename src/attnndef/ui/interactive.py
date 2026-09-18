from __future__ import annotations
import ipaddress
import os
import time
from typing import Any

from ..context import ContextStore, OperatorContext
from ..integrations import ReconService
from ..integrations.tool_runner import ToolRunner
from ..io.sink import LocalSink
from ..knowledge import list_ad_articles, list_gzctf_articles
from ..targets import Role, Scope, Target, TargetService, diff_history, compare_observations
from ..tools import (
    FfufAdapter,
    FfufService,
    GdbAdapter,
    GdbService,
    HttpAdapter,
    HttpService,
    HttpRequest,
    NmapAdapter,
    NmapService,
    SshAdapter,
    SshService,
    SystemAdapter,
    SystemService,
    TcpdumpAdapter,
    TcpdumpService,
    ToolExecutionRecord,
    validate_ports,
)

class InteractiveConsole:
    def __init__(
        self,
        store: ContextStore,
        input_fn=input,
        output_fn=print,
        recon_service: ReconService | None = None,
        scope: Scope | None = None,
        runner: ToolRunner | None = None,
        nmap_service: NmapService | None = None,
        http_service: HttpService | None = None,
        ffuf_service: FfufService | None = None,
        ssh_service: SshService | None = None,
        tcpdump_service: TcpdumpService | None = None,
        gdb_service: GdbService | None = None,
        system_service: SystemService | None = None,
        sink: LocalSink | None = None,
    ):
        self.store = store
        self.input = input_fn
        self.output = output_fn
        self.context = store.load()
        self.target_service = TargetService(store.path)
        self.recon_service = recon_service
        self.scope = scope
        self.sink = sink
        self.last_execution: ToolExecutionRecord | None = None

        self.runner = runner or ToolRunner()
        self.nmap_service = nmap_service or NmapService(NmapAdapter(self.runner))
        self.http_service = http_service or HttpService(HttpAdapter(self.runner))
        self.ffuf_service = ffuf_service or FfufService(FfufAdapter(self.runner))
        self.ssh_service = ssh_service or SshService(SshAdapter(self.runner))
        self.tcpdump_service = tcpdump_service or TcpdumpService(TcpdumpAdapter(self.runner))
        self.gdb_service = gdb_service or GdbService(GdbAdapter(self.runner))
        self.system_service = system_service or SystemService(SystemAdapter(self.runner))

    def _ask(self, label: str, default: str = "") -> str:
        prompt = f"{label}{f' [{default}]' if default else ''}: "
        value = self.input(prompt).strip()
        return value or default

    def _target_or_selected(self) -> Target | None:
        tid = self.context.selected_target or self._ask("Target ID")
        target = self.target_service.get_target(tid)
        if target is None:
            self.output("Target not found.")
        return target

    def _show_observation(self, observation):
        self.output(f"Observation #{observation.id}\nStatus: {observation.status}\nServices:")
        for service in observation.services:
            self.output(f"  {service.port}/{service.protocol}  {service.name}  {service.version}".rstrip())

    def _scan_target(self):
        target = self._target_or_selected()
        if target is None:
            return
        if self.recon_service is None or self.scope is None:
            self.output("Scan is not configured; no operation was performed.")
            return
        try:
            observation = self.recon_service.scan_target(
                target,
                self.scope,
                session_id=self.context.session_id,
                round_id=self.context.current_round,
            )
        except ValueError as exc:
            self.output(f"Scan rejected: {exc}")
            return
        except Exception as exc:
            self.output(f"Scan failed: {exc}")
            return
        self._show_observation(observation)
        history = self.target_service.history(target.id)
        if len(history) > 1:
            intelligence = diff_history(history)
            self.output(
                f"Changes since observation #{intelligence.previous_id}:\n{intelligence.render()}"
                if intelligence and intelligence.entries
                else "No intelligence changes since the previous observation."
            )
        else:
            self.output("No previous observation.")

    def _compare_observations(self):
        target = self._target_or_selected()
        if target is None:
            return
        history = self.target_service.history(target.id)
        if not history:
            self.output("No observations.")
            return
        self.output("Observations:\n" + "\n".join(f"  #{o.id}  round={o.round_id}  status={o.status}" for o in history))
        older_id = int(self._ask("Older observation ID"))
        newer_id = int(self._ask("Newer observation ID"))
        observations = {o.id: o for o in history}
        if older_id not in observations or newer_id not in observations:
            self.output("Observation not found.")
            return
        self.output(compare_observations(observations[older_id], observations[newer_id]).render())

    def _targets_menu(self):
        while True:
            self.output(
                "TARGETS\n"
                "  1. List Targets\n"
                "  2. Select Target\n"
                "  3. Add Target\n"
                "  4. Edit Target\n"
                "  5. Remove Target\n"
                "  6. Target Details\n"
                "  7. Intelligence History\n"
                "  8. Scan Target\n"
                "  9. Compare Observations\n"
                "  0. Back"
            )
            choice = self._ask("Select", "0")
            if choice == "0":
                return
            if choice == "1":
                rows = self.target_service.list_targets()
                self.output("\n".join(f"{t.id}  {t.name}  {t.host}  {t.role.value}  [{', '.join(t.tags)}]" for t in rows) or "No targets.")
            elif choice == "2":
                target = self.target_service.get_target(self._ask("Target ID"))
                if target is None:
                    self.output("Target not found.")
                else:
                    self.context.selected_target = target.id
                    self.store.save(self.context)
                    self.output(f"Selected target: {target.name} ({target.host})")
            elif choice == "3":
                role = self._ask("Role", "unknown").lower()
                try:
                    role_enum = Role(role)
                except ValueError:
                    self.output("Invalid role.")
                    continue
                tags = tuple(x.strip() for x in self._ask("Tags (comma separated)").split(",") if x.strip())
                self.target_service.add_target(Target(self._ask("ID"), self._ask("Name"), self._ask("Host"), role_enum, tags))
                self.output("Target added.")
            elif choice == "4":
                tid = self._ask("Target ID")
                current = self.target_service.get_target(tid)
                if current is None:
                    self.output("Target not found.")
                else:
                    role = self._ask("Role", current.role.value).lower()
                    try:
                        role_enum = Role(role)
                    except ValueError:
                        self.output("Invalid role.")
                        continue
                    tags = tuple(x.strip() for x in self._ask("Tags", ",".join(current.tags)).split(",") if x.strip())
                    self.target_service.update_target(
                        tid,
                        name=self._ask("Name", current.name),
                        host=self._ask("Host", current.host),
                        role=role_enum,
                        tags=tags,
                        notes=self._ask("Notes", current.notes),
                    )
                    self.output("Target updated.")
            elif choice == "5":
                self.output("Removed." if self.target_service.remove_target(self._ask("Target ID")) else "Target not found.")
            elif choice in {"6", "7"}:
                target = self._target_or_selected()
                if choice == "6":
                    self.output(str(target) if target else "Target not found.")
                else:
                    self.output("\n".join(str(o) for o in self.target_service.history(target.id)) if target else "Target not found.")
            elif choice == "8":
                self._scan_target()
            elif choice == "9":
                self._compare_observations()

    def _review_parameters(self, title: str, params: dict[str, str], note: str = "") -> bool:
        self.output(f"\n{title}\n" + "─" * 28)
        max_len = max((len(k) for k in params), default=0)
        for k, v in params.items():
            self.output(f"  {k.ljust(max_len)} : {v}")
        if note:
            self.output(f"  {'Note'.ljust(max_len)} : {note}")
        choice = self._ask("\nExecute? [y/N]", "N").lower()
        if choice not in ("y", "yes"):
            self.output("Operation cancelled.")
            return False
        return True

    def _present_success(self, tool: str, target: str, duration_s: float, details: str = ""):
        self.output(f"\n✓ {tool} completed")
        self.output(f"  Target:   {target}")
        self.output(f"  Duration: {duration_s:.2f}s")
        if details:
            self.output(f"\n{details}")

    def _present_failure(self, tool: str, target: str, duration_s: float, reason: str, details: str = ""):
        self.output(f"\n✗ {tool} failed\n")
        self.output(f"Reason:   {reason}")
        self.output(f"Target:   {target}")
        self.output(f"Duration: {duration_s:.2f}s")
        if details:
            self.output(f"\n{details}")

    def _record_execution(
        self,
        tool: str,
        operation: str,
        target: str,
        duration_s: float,
        parameters: dict[str, Any],
        success: bool,
        returncode: int | None = 0,
        error_kind: str | None = None,
        error: str | None = None,
        summary: str = "",
        details: dict[str, Any] | None = None,
    ):
        record = ToolExecutionRecord(
            tool=tool,
            operation=operation,
            target=target,
            timestamp=time.time(),
            duration_s=duration_s,
            parameters=parameters,
            success=success,
            returncode=returncode,
            error_kind=error_kind,
            error=error,
            output_summary=summary,
            details=details or {},
        )
        self.last_execution = record
        if self.sink is not None:
            choice = self._ask("Save as evidence? [y/N]", "N").lower()
            if choice in ("y", "yes"):
                ev = record.to_evidence()
                self.sink.write(ev)
                self.output(f"✓ Evidence recorded: {ev.id}")

    def _resolve_target_and_scope(self, default_host: str = "") -> tuple[bool, Target | None, str]:
        target: Target | None = None
        def_h = default_host
        if self.context.selected_target:
            target = self.target_service.get_target(self.context.selected_target)
            if target:
                def_h = target.host
        host = self._ask("Target Host / IP", def_h)
        if not host:
            self.output("Host is required.")
            return False, None, ""
        if target and host == target.host and self.scope:
            allowed, reason = self.scope.validate(target)
            if not allowed:
                self.output(f"\n✗ Scope check rejected: {reason}")
                return False, target, host
        elif self.scope and self.scope.allowed_networks:
            try:
                addr = ipaddress.ip_address(host)
                if not any(addr in ipaddress.ip_network(net, strict=False) for net in self.scope.allowed_networks):
                    self.output(f"\n✗ Scope check rejected: host {host} is outside allowed networks")
                    return False, None, host
            except ValueError:
                pass
        return True, target, host

    def _tools_menu(self):
        while True:
            target_str = "(none)"
            if self.context.selected_target:
                t = self.target_service.get_target(self.context.selected_target)
                if t:
                    target_str = f"{t.name} ({t.host}) [{t.role.value}]"
            self.output(
                f"Tools\n"
                f"────────────────────────────\n"
                f"Active Target: {target_str}\n\n"
                f"  1. Nmap\n"
                f"  2. HTTP\n"
                f"  3. ffuf\n"
                f"  4. SSH\n"
                f"  5. tcpdump\n"
                f"  6. GDB\n"
                f"  7. System Diagnostics\n"
                f"  0. Back"
            )
            choice = self._ask("Select", "0")
            if choice == "0":
                return
            if choice == "1":
                self._tool_nmap()
            elif choice == "2":
                self._tool_http()
            elif choice == "3":
                self._tool_ffuf()
            elif choice == "4":
                self._tool_ssh()
            elif choice == "5":
                self._tool_tcpdump()
            elif choice == "6":
                self._tool_gdb()
            elif choice == "7":
                self._tool_system()

    def _tool_nmap(self):
        while True:
            self.output(
                "Nmap\n"
                "────────────────────────────\n"
                "  1. Host Discovery\n"
                "  2. Port Scan\n"
                "  3. Service Detection\n"
                "  0. Back"
            )
            mode = self._ask("Select", "0")
            if mode == "0":
                return
            if mode == "1":
                network = self._ask("Network CIDR", self.context.enemy_subnet or "10.0.0.0/24")
                if not self._review_parameters(
                    "Nmap Host Discovery",
                    {
                        "Operation": "Host Discovery (-sn)",
                        "Network": network,
                        "Timeout": "30s",
                        "Bounded": "Yes (timeout 30s)",
                    },
                ):
                    continue
                try:
                    res, hosts = self.nmap_service.discover_detailed(network)
                    if res.success:
                        details = f"Discovered {len(hosts)} hosts:\n" + "\n".join(f"  {h.host} ({h.status})" for h in hosts) if hosts else "No hosts discovered."
                        self._present_success("Nmap", network, res.duration_s, details)
                    else:
                        self._present_failure("Nmap", network, res.duration_s, res.error_kind or "nonzero_exit", res.stderr or res.error or "")
                    self._record_execution(
                        "nmap", "host_discovery", network, res.duration_s,
                        {"network": network}, res.success, res.returncode, res.error_kind, res.error or res.stderr,
                        f"Discovered {len(hosts)} hosts", {"hosts": [h.__dict__ for h in hosts]},
                    )
                except Exception as exc:
                    self._present_failure("Nmap", network, 0.0, "exception", str(exc))
            elif mode in {"2", "3"}:
                op_name = "Port Scan" if mode == "2" else "Service Detection"
                valid, target, host = self._resolve_target_and_scope()
                if not valid:
                    continue
                raw_ports = self._ask("Ports", "1-1024")
                try:
                    ports = validate_ports(raw_ports)
                except ValueError as exc:
                    self.output(f"Invalid ports: {exc}")
                    continue
                tgt_label = f"{target.name} ({target.host})" if target else host
                params = {
                    "Operation": f"Nmap {op_name}",
                    "Target": tgt_label,
                    "Host": host,
                    "Ports": ports,
                    "Mode": "scoped target scan" if target else "unscoped scan",
                    "Bounded": "Yes (timeout 30s)",
                }
                if not self._review_parameters(f"Nmap {op_name}", params):
                    continue
                try:
                    if target and self.recon_service and self.scope:
                        observation = self.recon_service.scan_target(
                            target,
                            self.scope,
                            session_id=self.context.session_id,
                            round_id=self.context.current_round,
                            ports=ports,
                        )
                        services = observation.services
                        dur = float(observation.metadata.get("duration_s", 0.0))
                        srv_lines = "\n".join(f"  {s.port}/{s.protocol:<4} {s.name:<12} {s.version}".rstrip() for s in services) or "  (none)"
                        details = f"Open Services\n──────────────\n{srv_lines}"
                        history = self.target_service.history(target.id)
                        if len(history) > 1:
                            intel = diff_history(history)
                            if intel and intel.entries:
                                details += f"\n\nChanges since observation #{intel.previous_id}:\n{intel.render()}"
                        self._present_success("Nmap", host, dur, details)
                        self._record_execution(
                            "nmap", op_name.lower().replace(" ", "_"), host, dur,
                            {"host": host, "ports": ports, "target_id": target.id},
                            True, 0, "success", None,
                            f"Found {len(services)} open services", {"services": [s.__dict__ for s in services]},
                        )
                    else:
                        res, services = self.nmap_service.scan_target_detailed(
                            host, ports=ports, service_detection=(mode == "3")
                        )
                        if res.success:
                            srv_lines = "\n".join(f"  {s.port}/{s.protocol:<4} {s.name:<12} {s.version}".rstrip() for s in services) or "  (none)"
                            details = f"Open Services\n──────────────\n{srv_lines}"
                            self._present_success("Nmap", host, res.duration_s, details)
                        else:
                            self._present_failure("Nmap", host, res.duration_s, res.error_kind or "nonzero_exit", res.stderr or res.error or "")
                        self._record_execution(
                            "nmap", op_name.lower().replace(" ", "_"), host, res.duration_s,
                            {"host": host, "ports": ports},
                            res.success, res.returncode, res.error_kind, res.error or res.stderr,
                            f"Found {len(services)} open services", {"services": [s.__dict__ for s in services]},
                        )
                except Exception as exc:
                    self._present_failure("Nmap", host, 0.0, "exception", str(exc))

    def _tool_http(self):
        while True:
            self.output(
                "HTTP\n"
                "────────────────────────────\n"
                "  1. GET\n"
                "  2. POST\n"
                "  0. Back"
            )
            mode = self._ask("Select", "0")
            if mode == "0":
                return
            if mode not in {"1", "2"}:
                self.output("Invalid selection.")
                continue
            method = "GET" if mode == "1" else "POST"
            def_url = ""
            if self.context.selected_target:
                t = self.target_service.get_target(self.context.selected_target)
                if t:
                    def_url = f"http://{t.host}/"
            url = self._ask("URL", def_url or "http://127.0.0.1:8080/")
            timeout_str = self._ask("Timeout (s)", "10")
            try:
                timeout_s = float(timeout_str)
            except ValueError:
                self.output("Invalid timeout.")
                continue
            headers_raw = self._ask("Headers (optional, e.g. Auth:Token)", "")
            headers: dict[str, str] = {}
            if headers_raw:
                for part in headers_raw.split(","):
                    if ":" in part:
                        k, v = part.split(":", 1)
                        headers[k.strip()] = v.strip()
            body = self._ask("Request Body (optional)") if method == "POST" else None

            params = {
                "Method": method,
                "URL": url,
                "Timeout": f"{timeout_s:.1f}s",
                "Headers": str(headers) if headers else "(none)",
            }
            if body is not None:
                params["Body"] = body[:50] + ("..." if len(body) > 50 else "")
            params["Bounded"] = f"Yes (max-time {int(timeout_s)}s)"

            if not self._review_parameters(f"HTTP {method}", params):
                continue

            try:
                res, resp = self.http_service.adapter.execute(
                    HttpRequest(url=url, method=method, headers=headers, body=body, timeout_s=timeout_s)
                )
                if resp.status_code > 0:
                    hdr_lines = "\n".join(f"    {k}: {v}" for k, v in list(resp.headers.items())[:8]) or "    (none)"
                    body_preview = resp.body[:400] + ("..." if len(resp.body) > 400 else "")
                    details = f"  Status:   {resp.status_code}\n  Headers:\n{hdr_lines}\n  Body:\n{body_preview}"
                    self._present_success(f"HTTP {method}", url, resp.duration_s, details)
                else:
                    self._present_failure(f"HTTP {method}", url, resp.duration_s, resp.error_kind or "nonzero_exit", resp.error or res.stderr)
                self._record_execution(
                    "http", method.lower(), url, resp.duration_s,
                    {"url": url, "method": method, "timeout_s": timeout_s},
                    resp.success, resp.returncode, resp.error_kind, resp.error,
                    f"HTTP {resp.status_code}", {"status_code": resp.status_code},
                )
            except Exception as exc:
                self._present_failure(f"HTTP {method}", url, 0.0, "exception", str(exc))

    def _tool_ffuf(self):
        while True:
            self.output(
                "ffuf\n"
                "────────────────────────────\n"
                "  1. Endpoint Discovery\n"
                "  0. Back"
            )
            mode = self._ask("Select", "0")
            if mode == "0":
                return
            if mode != "1":
                self.output("Invalid selection.")
                continue
            def_url = ""
            if self.context.selected_target:
                t = self.target_service.get_target(self.context.selected_target)
                if t:
                    def_url = f"http://{t.host}/FUZZ"
            url = self._ask("URL with FUZZ", def_url or "http://127.0.0.1/FUZZ")
            wordlist = self._ask("Wordlist path", "/usr/share/wordlists/dirb/common.txt")
            if not os.path.exists(wordlist):
                self.output(f"Wordlist not found: {wordlist}")
                continue
            exts_raw = self._ask("Extensions (optional, comma-separated e.g. php,txt)", "")
            exts = tuple(x.strip() for x in exts_raw.split(",") if x.strip())
            timeout_str = self._ask("Timeout (s)", "30")
            try:
                timeout_s = float(timeout_str)
            except ValueError:
                self.output("Invalid timeout.")
                continue

            params = {
                "Operation": "Endpoint Discovery",
                "URL": url,
                "Wordlist": wordlist,
                "Extensions": ",".join(exts) if exts else "(none)",
                "Bounded": f"Yes (timeout {timeout_s:.1f}s)",
            }
            if not self._review_parameters("ffuf Endpoint Discovery", params):
                continue

            try:
                res = self.ffuf_service.discover_endpoints(
                    url, wordlist, extensions=exts, timeout_s=timeout_s
                )
                if res.success:
                    match_lines = "\n".join(
                        f"  [{m.status}] len={m.length:<5} words={m.words:<4} lines={m.lines:<4} {m.url}" + (f" -> {m.redirect_location}" if m.redirect_location else "")
                        for m in res.matches[:20]
                    ) or "  (no matches)"
                    details = f"Discovered Endpoints ({len(res.matches)}):\n{match_lines}"
                    self._present_success("ffuf", url, res.duration_s, details)
                else:
                    self._present_failure("ffuf", url, res.duration_s, res.error_kind or "nonzero_exit", res.error or "")
                self._record_execution(
                    "ffuf", "discover_endpoints", url, res.duration_s,
                    {"url": url, "wordlist": wordlist, "extensions": exts},
                    res.success, res.returncode, res.error_kind, res.error,
                    f"Found {len(res.matches)} endpoints", {"matches_count": len(res.matches)},
                )
            except Exception as exc:
                self._present_failure("ffuf", url, 0.0, "exception", str(exc))

    def _tool_ssh(self):
        while True:
            self.output(
                "SSH\n"
                "────────────────────────────\n"
                "  1. Execute Diagnostic Command\n"
                "  0. Back"
            )
            mode = self._ask("Select", "0")
            if mode == "0":
                return
            if mode != "1":
                self.output("Invalid selection.")
                continue

            self.output(
                "\nDiagnostic Operations:\n"
                "  1. Service Status (systemctl status)\n"
                "  2. System Uptime & Load (uptime)\n"
                "  3. Listening Sockets (ss -tulpn)\n"
                "  4. Process List (ps aux)\n"
                "  5. Diagnostic File Read (cat)\n"
                "  6. Custom Diagnostic Command\n"
                "  0. Back"
            )
            diag_choice = self._ask("Select", "0")
            if diag_choice == "0":
                continue
            if diag_choice == "1":
                svc_name = self._ask("Service Name (e.g. nginx)", "nginx")
                command = f"systemctl status {svc_name} --no-pager"
            elif diag_choice == "2":
                command = "uptime"
            elif diag_choice == "3":
                command = "ss -tulpn"
            elif diag_choice == "4":
                command = "ps aux"
            elif diag_choice == "5":
                file_path = self._ask("Remote File Path", "/etc/hosts")
                command = f"cat {file_path}"
            elif diag_choice == "6":
                command = self._ask("Diagnostic Command", "uname -a")
            else:
                self.output("Invalid selection.")
                continue

            def_host = ""
            if self.context.selected_target:
                t = self.target_service.get_target(self.context.selected_target)
                if t:
                    def_host = t.host
            host = self._ask("Host", def_host or self.context.own_ip or "127.0.0.1")
            try:
                port = int(self._ask("SSH Port", "22"))
            except ValueError:
                self.output("Invalid port.")
                continue
            user = self._ask("User", "root")
            key = self._ask("Identity Key File", "~/.ssh/id_rsa")
            timeout_str = self._ask("Timeout (s)", "15")
            try:
                timeout_s = float(timeout_str)
            except ValueError:
                self.output("Invalid timeout.")
                continue

            params = {
                "Operation": "SSH Diagnostic Command",
                "Host": host,
                "Port": str(port),
                "User": user,
                "Key": key,
                "Command": command,
                "Mode": "Non-interactive BatchMode",
                "Bounded": f"Yes (timeout {timeout_s:.1f}s)",
            }
            if not self._review_parameters("SSH Execution", params):
                continue

            try:
                res = self.ssh_service.run(
                    host, command, port=port, username=user, identity_file=key, timeout_s=timeout_s
                )
                if res.success:
                    details = f"Exit: {res.returncode}\nOutput:\n{res.stdout}"
                    if res.stderr:
                        details += f"\nStderr:\n{res.stderr}"
                    self._present_success("SSH", f"{user}@{host}:{port}", res.duration_s, details)
                else:
                    self._present_failure("SSH", f"{user}@{host}:{port}", res.duration_s, res.error_kind or "nonzero_exit", res.stderr or res.error or "")
                self._record_execution(
                    "ssh", "diagnostic_command", host, res.duration_s,
                    {"host": host, "port": port, "user": user, "command": command},
                    res.success, res.returncode, res.error_kind, res.error,
                    f"Exit {res.returncode}", {"stdout_len": len(res.stdout)},
                )
            except Exception as exc:
                self._present_failure("SSH", host, 0.0, "exception", str(exc))

    def _tool_tcpdump(self):
        while True:
            self.output(
                "tcpdump\n"
                "────────────────────────────\n"
                "  1. Packet Capture\n"
                "  0. Back"
            )
            mode = self._ask("Select", "0")
            if mode == "0":
                return
            if mode != "1":
                self.output("Invalid selection.")
                continue

            iface = self._ask("Interface", self.context.vpn_interface or "any")
            try:
                duration_s = float(self._ask("Duration (s)", "5"))
                packet_count = int(self._ask("Packet Count", "50"))
            except ValueError:
                self.output("Invalid duration or count.")
                continue
            bpf = self._ask("BPF filter (optional, e.g. tcp port 80)", "")

            params = {
                "Operation": "Packet Capture",
                "Interface": iface,
                "Duration": f"{duration_s:.1f}s",
                "Packets": str(packet_count),
                "Filter": bpf or "(all)",
                "Bounded": "Yes (duration <= 300s, max 10000 pkts)",
            }
            if not self._review_parameters("tcpdump Packet Capture", params):
                continue

            try:
                res = self.tcpdump_service.capture_live(
                    interface=iface, duration_s=duration_s, packet_count=packet_count, bpf_filter=bpf
                )
                if res.success:
                    preview = res.raw_output[:800] + ("..." if len(res.raw_output) > 800 else "")
                    self._present_success("tcpdump", iface, res.duration_s, f"Captured Packets:\n{preview}")
                else:
                    self._present_failure("tcpdump", iface, res.duration_s, res.error_kind or "nonzero_exit", res.error or "")
                self._record_execution(
                    "tcpdump", "capture", iface, res.duration_s,
                    {"interface": iface, "duration_s": duration_s, "packet_count": packet_count, "bpf_filter": bpf},
                    res.success, res.returncode, res.error_kind, res.error,
                    f"Captured on {iface}", {"raw_output_len": len(res.raw_output)},
                )
            except Exception as exc:
                self._present_failure("tcpdump", iface, 0.0, "exception", str(exc))

    def _tool_gdb(self):
        while True:
            self.output(
                "GDB\n"
                "────────────────────────────\n"
                "  1. Binary Inspection\n"
                "  2. Crash Analysis / Backtrace\n"
                "  3. Inspect Registers\n"
                "  4. Memory Inspection\n"
                "  0. Back"
            )
            mode = self._ask("Select", "0")
            if mode == "0":
                return
            if mode not in {"1", "2", "3", "4"}:
                self.output("Invalid selection.")
                continue

            binary = self._ask("Target Binary Path")
            if not os.path.exists(binary):
                self.output(f"Binary not found: {binary}")
                continue

            core: str | None = None
            sym = "main"
            if mode in {"2", "3"}:
                core = self._ask("Core Dump Path (optional)") or None
            elif mode == "4":
                sym = self._ask("Address or Symbol (e.g. main, *0x401000)", "main")

            op_names = {
                "1": "Binary Inspection",
                "2": "Crash Analysis",
                "3": "Register Inspection",
                "4": "Memory Inspection",
            }
            op_title = op_names[mode]
            params = {
                "Operation": f"GDB {op_title}",
                "Binary": binary,
                "Core": core or "(none)",
                "Mode": "Non-interactive batch mode (--batch)",
                "Bounded": "Yes (timeout 15s)",
            }
            if mode == "4":
                params["Target Spec"] = sym

            if not self._review_parameters(f"GDB {op_title}", params):
                continue

            try:
                if mode == "1":
                    res = self.gdb_service.inspect_binary(binary)
                elif mode == "2":
                    res = self.gdb_service.analyze_crash(binary, core_path=core)
                elif mode == "3":
                    res = self.gdb_service.inspect_registers(binary, core_path=core)
                else:
                    res = self.gdb_service.inspect_memory(binary, address_or_symbol=sym, core_path=core)

                if res.success:
                    preview = res.stdout[:1000] + ("..." if len(res.stdout) > 1000 else "")
                    self._present_success("GDB", binary, res.duration_s, f"GDB Output:\n{preview}")
                else:
                    self._present_failure("GDB", binary, res.duration_s, res.error_kind or "nonzero_exit", res.stderr or res.error or "")
                self._record_execution(
                    "gdb", op_title.lower().replace(" ", "_"), binary, res.duration_s,
                    {"binary": binary, "commands": res.commands},
                    res.success, res.returncode, res.error_kind, res.error,
                    f"GDB {op_title}", {"commands": res.commands},
                )
            except Exception as exc:
                self._present_failure("GDB", binary, 0.0, "exception", str(exc))

    def _tool_system(self):
        while True:
            self.output(
                "System Diagnostics\n"
                "────────────────────────────\n"
                "  1. Listening Sockets (ss -tulpn)\n"
                "  2. Connections (ss -tan)\n"
                "  3. Processes (ps aux)\n"
                "  4. Service Status (systemctl status)\n"
                "  5. Network Addresses (ip addr)\n"
                "  6. Routing Table (ip route)\n"
                "  7. DNS Lookup (dig)\n"
                "  8. WireGuard Status (wg show)\n"
                "  0. Back"
            )
            choice = self._ask("Select", "0")
            if choice == "0":
                return

            op_map = {
                "1": ("Listening Sockets", "ss -tulpn"),
                "2": ("All TCP Sockets", "ss -tan"),
                "3": ("Process List", "ps aux"),
                "4": ("Service Status", "systemctl status"),
                "5": ("Network Addresses", "ip addr"),
                "6": ("Routing Table", "ip route"),
                "7": ("DNS Lookup", "dig"),
                "8": ("WireGuard Status", "wg show"),
            }
            if choice not in op_map:
                self.output("Invalid selection.")
                continue

            title, cmd_label = op_map[choice]
            svc_name = ""
            domain = ""
            if choice == "4":
                svc_name = self._ask("Service Name (e.g. nginx)", "nginx")
                cmd_label = f"systemctl status {svc_name} --no-pager"
            elif choice == "7":
                domain = self._ask("Domain", "jjz.jatimprov.go.id")
                cmd_label = f"dig +short {domain} A"
            elif choice == "8":
                iface = self.context.vpn_interface or "wg0"
                cmd_label = f"wg show {iface}"

            params = {
                "Operation": title,
                "Command": cmd_label,
                "Bounded": "Yes (timeout 10s)",
            }
            if not self._review_parameters(f"System: {title}", params):
                continue

            try:
                if choice == "1":
                    res = self.system_service.ss_listening()
                elif choice == "2":
                    res = self.system_service.ss_all()
                elif choice == "3":
                    res = self.system_service.ps_aux()
                elif choice == "4":
                    res = self.system_service.systemctl_status(svc_name)
                elif choice == "5":
                    res = self.system_service.ip_addr()
                elif choice == "6":
                    res = self.system_service.ip_route()
                elif choice == "7":
                    res = self.system_service.dig_lookup(domain)
                elif choice == "8":
                    res = self.system_service.wireguard_status(self.context.vpn_interface)
                else:
                    return

                if res.success:
                    details = f"Command: {res.tool} {res.subcommand}\nExit: {res.returncode}\n{res.stdout}"
                    if res.stderr:
                        details += f"\nStderr:\n{res.stderr}"
                    self._present_success(f"System ({res.tool})", "localhost", res.duration_s, details)
                else:
                    self._present_failure(f"System ({res.tool})", "localhost", res.duration_s, res.error_kind or "nonzero_exit", res.stderr or res.error or "")
                self._record_execution(
                    "system", res.tool, "localhost", res.duration_s,
                    {"tool": res.tool, "subcommand": res.subcommand},
                    res.success, res.returncode, res.error_kind, res.error,
                    f"[{res.tool}] exit={res.returncode}",
                )
            except Exception as exc:
                self._present_failure("System", "localhost", 0.0, "exception", str(exc))

    def _ad_menu(self):
        articles = list_ad_articles()
        while True:
            self.output("ATTACK & DEFENSE KNOWLEDGE")
            for i, art in enumerate(articles, 1):
                self.output(f"  {i}. {art.title} — {art.summary}")
            self.output("  0. Back")
            choice = self._ask("Select", "0")
            if choice == "0":
                return
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(articles):
                    self.output(f"\n{articles[idx].content}\n")
                else:
                    self.output("Invalid selection.")
            except ValueError:
                self.output("Invalid selection.")

    def _gzctf_menu(self):
        articles = list_gzctf_articles()
        while True:
            self.output("GZCTF PLATFORM GUIDE")
            for i, art in enumerate(articles, 1):
                self.output(f"  {i}. {art.title} — {art.summary}")
            self.output("  0. Back")
            choice = self._ask("Select", "0")
            if choice == "0":
                return
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(articles):
                    self.output(f"\n{articles[idx].content}\n")
                else:
                    self.output("Invalid selection.")
            except ValueError:
                self.output("Invalid selection.")

    def _competition_menu(self):
        while True:
            self.output(
                "COMPETITION STATUS\n"
                f"  Platform:         {self.context.platform or 'jjz.jatimprov.go.id'}\n"
                f"  Competition Name: {self.context.competition_name or 'Grand Final Attack & Defense'}\n"
                f"  Team:             {self.context.team_name or '(unset)'} (ID: {self.context.team_id or '(unset)'})\n"
                f"  VPN Interface:    {self.context.vpn_interface or 'wg0'}\n"
                f"  Active Round:     {self.context.current_round}\n"
                f"  Selected Target:  {self.context.selected_target or '(none)'}\n\n"
                "  1. WireGuard Status Check\n"
                "  2. Set Local Active Round (tracking only)\n"
                "  3. Set Target Subnet\n"
                "  0. Back"

            )
            choice = self._ask("Select", "0")
            if choice == "0":
                return
            if choice == "1":
                res = self.system_service.wireguard_status(self.context.vpn_interface)
                self.output(f"WireGuard Status:\n{res.stdout or '(no active WireGuard interface)'}")
            elif choice == "2":
                rnd = self._ask("Active Round Number", str(self.context.current_round + 1))
                try:
                    self.context.current_round = int(rnd)
                    self.store.save(self.context)
                    self.output(f"Active round set to {self.context.current_round}.")
                except ValueError:
                    self.output("Invalid round number.")
            elif choice == "3":
                sub = self._ask("Enemy Subnet CIDR", self.context.enemy_subnet or "10.0.0.0/24")
                self.context.enemy_subnet = sub
                self.store.save(self.context)
                self.output(f"Enemy subnet updated to {sub}.")

    def _settings_menu(self):
        while True:
            self.output(
                "SETTINGS\n"
                f"  Profile:          {self.context.profile}\n"
                f"  Operator:         {self.context.operator_name or '(unset)'}\n"
                f"  Team:             {self.context.team_name or '(unset)'} (ID: {self.context.team_id or '(unset)'})\n"
                f"  VPN Interface:    {self.context.vpn_interface or 'wg0'}\n"
                f"  Own IP:           {self.context.own_ip or '(unset)'}\n"
                f"  Enemy Subnet:     {self.context.enemy_subnet or '(unset)'}\n"
                f"  Platform:         {self.context.platform or 'jjz.jatimprov.go.id'}\n"
                f"  Flag Format:      {self.context.flag_format or 'flag{...}'}\n\n"
                "  1. Edit Profile Settings\n"
                "  0. Back"
            )
            choice = self._ask("Select", "0")
            if choice == "0":
                return
            if choice == "1":
                self.context.operator_name = self._ask("Operator Name", self.context.operator_name)
                self.context.team_name = self._ask("Team Name", self.context.team_name)
                self.context.team_id = self._ask("Team ID", self.context.team_id)
                self.context.vpn_interface = self._ask("VPN Interface", self.context.vpn_interface or "wg0")
                self.context.own_ip = self._ask("Own IP", self.context.own_ip)
                self.context.enemy_subnet = self._ask("Enemy Subnet", self.context.enemy_subnet)
                self.context.platform = self._ask("Platform", self.context.platform or "jjz.jatimprov.go.id")
                self.context.flag_format = self._ask("Flag Format", self.context.flag_format or "flag{...}")
                self.store.save(self.context)
                self.output("Settings saved.")

    def wizard(self):
        self.output("\nATTNNDEF — Attack & Defense Operator Console\nNo operator configuration found.\n")
        choices = {"1": "Local Attack & Defense", "2": "Competition (GZCTF)"}
        mode = choices.get(self._ask("Profile [1-2]", "2"), "Competition (GZCTF)")
        self.context = OperatorContext(profile=mode)
        self.context.operator_name = self._ask("Operator Name")
        self.context.team_name = self._ask("Team Name")
        self.context.team_id = self._ask("Team ID")
        self.context.vpn_interface = self._ask("VPN Interface", "wg0")
        self.context.own_ip = self._ask("Own IP (optional)")
        self.context.team_subnet = self._ask("Team subnet (optional)")
        self.context.enemy_subnet = self._ask("Enemy subnet (optional)")
        self.context.platform = self._ask("Platform", "jjz.jatimprov.go.id")
        self.context.competition_name = self._ask("Competition name", "Grand Final Attack & Defense")
        self.context.flag_format = self._ask("Flag format", "flag{...}")
        self.store.save(self.context)
        self.output("Configuration saved.\n")

    def run(self):
        try:
            if self.context is None:
                self.wizard()
            while True:
                self.output(
                    "ATTNNDEF\n"
                    "────────────────────────────\n"
                    "  1. Targets\n"
                    "  2. Tools\n"
                    "  3. Attack & Defense\n"
                    "  4. GZCTF\n"
                    "  5. Competition\n"
                    "  6. Settings\n"
                    "  0. Exit"
                )
                choice = self._ask("Select", "0")
                if choice == "0" or choice.lower() in {"q", "quit", "exit"}:
                    self.output("Bye.")
                    return 0
                if choice == "1":
                    self._targets_menu()
                elif choice == "2":
                    self._tools_menu()
                elif choice == "3":
                    self._ad_menu()
                elif choice == "4":
                    self._gzctf_menu()
                elif choice == "5":
                    self._competition_menu()
                elif choice == "6":
                    self._settings_menu()
                else:
                    self.output("Invalid selection.")
        except (EOFError, KeyboardInterrupt):
            self.output("\nSession closed.")
            return 0
