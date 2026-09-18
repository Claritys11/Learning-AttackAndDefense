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
from ..operations import (
    ActionCategory,
    AttackRecord,
    AttackStatus,
    DefenseRecord,
    DefenseStatus,
    FlagRecord,
    FlagStatus,
    Mission,
    MissionStatus,
    OperationService,
    OperatorAction,
    RoundStatus,
    SlaObservation,
    SlaStatus,
    WorkflowRun,
    WorkflowStatus,
)
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
        operation_service: OperationService | None = None,
    ):
        self.store = store
        self.input = input_fn
        self.output = output_fn
        self.context = store.load()
        self.target_service = TargetService(store.path)
        self.operation_service = operation_service or OperationService(store.path, target_service=self.target_service)
        if self.context and not self.context.session_id:
            active_s = self.operation_service.get_active_session()
            if active_s:
                self.context.session_id = active_s.session_id
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
        ev_id: str | None = None
        if self.sink is not None:
            choice = self._ask("Save as evidence? [y/N]", "N").lower()
            if choice in ("y", "yes"):
                ev = record.to_evidence()
                self.sink.write(ev)
                ev_id = ev.id
                self.output(f"✓ Evidence recorded: {ev.id}")
            act_choice = self._ask("Record as Operator Action? [y/N]", "N").lower()
            if act_choice in ("y", "yes"):
                cat_default = "recon" if tool in ("nmap", "ffuf") else ("system" if tool in ("sys", "tcpdump") else "verification")
                cat_str = self._ask(f"Category (recon/attack/defense/flag/verification/system)", cat_default).lower()
                try:
                    category = ActionCategory(cat_str)
                except ValueError:
                    category = ActionCategory.RECON
                sum_str = self._ask("Action Summary", summary or f"{tool} {operation}")
                session_id = self.context.session_id if self.context else ""
                round_id = self.context.current_round if self.context else 0

                wf_id = None
                m_id = None
                wf_choice = self._ask("Attach to workflow? [y/N]", "N").lower()
                if wf_choice in ("y", "yes"):
                    active_wfs = self.operation_service.list_workflows(status=WorkflowStatus.ACTIVE)
                    if active_wfs:
                        self.output("Active workflows:")
                        for w in active_wfs:
                            self.output(f"  [{w.workflow_id[:8]}] {w.title}")
                    wf_input = self._ask("Workflow ID (or prefix)", "").strip()
                    if wf_input:
                        matched = [w for w in active_wfs if w.workflow_id.startswith(wf_input)]
                        wf_id = matched[0].workflow_id if matched else wf_input

                    if wf_id:
                        m_choice = self._ask("Attach to mission? [y/N]", "N").lower()
                        if m_choice in ("y", "yes"):
                            active_ms = self.operation_service.list_missions(workflow_id=wf_id, status=MissionStatus.IN_PROGRESS)
                            if not active_ms:
                                active_ms = self.operation_service.list_missions(workflow_id=wf_id, status=MissionStatus.OPEN)
                            if active_ms:
                                self.output("Available missions:")
                                for m in active_ms:
                                    self.output(f"  [{m.mission_id[:8]}] {m.title} ({m.target_id}:{m.service_port})")
                            m_input = self._ask("Mission ID (or prefix)", "").strip()
                            if m_input:
                                matched = [m for m in active_ms if m.mission_id.startswith(m_input)]
                                m_id = matched[0].mission_id if matched else m_input

                parent_act_id = None
                if category == ActionCategory.VERIFICATION:
                    p_input = self._ask("Parent Action ID (optional, for verification linking)", "").strip()
                    parent_act_id = p_input or None

                act = self.operation_service.record_action(
                    session_id=session_id,
                    round_id=round_id,
                    category=category,
                    tool=tool,
                    operation=operation,
                    summary=sum_str,
                    target_id=self.context.selected_target if self.context else None,
                    status="completed" if success else "failed",
                    evidence_id=ev_id,
                    workflow_id=wf_id,
                    mission_id=m_id,
                    parent_action_id=parent_act_id,
                    tool_execution_id=record.id,
                    details={"parameters": parameters, "duration_s": duration_s},
                )
                wf_str = f" [WF: {act.workflow_id[:8]}]" if act.workflow_id else ""
                m_str = f" [Mission: {act.mission_id[:8]}]" if act.mission_id else ""
                self.output(f"✓ Operator Action recorded: [{act.category.value.upper()}]{wf_str}{m_str} {act.summary}")

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
        while True:
            rnd = self.context.current_round if self.context else 0
            self.output(
                "\nATTACK & DEFENSE OPERATIONS\n"
                "────────────────────────────\n"
                f"  Active Round: Round #{rnd} [LOCAL TRACKING]\n"
                f"  Platform:     {self.context.platform if self.context else 'jjz.jatimprov.go.id'}\n"
                f"  Sync Status:  Local round tracking (remote platform: not connected)\n\n"
                "  1. Current Round & Ticks\n"
                "  2. Operator Actions\n"
                "  3. Attack Records\n"
                "  4. Defense Records\n"
                "  5. Flag State\n"
                "  6. SLA / Health Observations\n"
                "  7. Activity Timeline\n"
                "  8. Workflows\n"
                "  9. Missions\n"
                "  10. Knowledge Base\n"
                "  0. Back"
            )
            choice = self._ask("Select", "0")
            if choice == "0":
                return
            elif choice == "1":
                self._ad_current_round()
            elif choice == "2":
                self._ad_actions()
            elif choice == "3":
                self._ad_attacks()
            elif choice == "4":
                self._ad_defenses()
            elif choice == "5":
                self._ad_flags()
            elif choice == "6":
                self._ad_sla()
            elif choice == "7":
                self._ad_timeline()
            elif choice == "8":
                self._ad_workflows()
            elif choice == "9":
                self._ad_missions()
            elif choice == "10":
                self._ad_knowledge()
            else:
                self.output("Invalid selection.")

    def _ad_current_round(self):
        while True:
            rnd = self.context.current_round if self.context else 0
            sid = self.context.session_id if self.context else "(none)"
            ticks = self.operation_service.list_ticks(rnd)
            active_r = self.operation_service.get_round(rnd)
            status_str = active_r.status.value.upper() if active_r else "ACTIVE"
            self.output(
                "\nCURRENT ROUND (LOCAL TRACKING)\n"
                "────────────────────────────\n"
                f"  Competition:  {self.context.competition_name if self.context else 'Grand Final Attack & Defense'}\n"
                f"  Session ID:   {sid}\n"
                f"  Round Number: #{rnd}\n"
                f"  Round Status: {status_str}\n"
                f"  Local Ticks:  {len(ticks)} ticks recorded\n"
                "  Notice:       Local round tracking | Remote platform state: not connected\n\n"
                "  1. Set / Advance Local Round\n"
                "  2. Complete Current Round\n"
                "  3. Record Local Tick Observation\n"
                "  0. Back"
            )
            choice = self._ask("Select", "0")
            if choice == "0":
                return
            if choice == "1":
                val = self._ask("New Round Number", str(rnd + 1))
                try:
                    new_rnd = int(val)
                    if self.context:
                        self.context.current_round = new_rnd
                        self.store.save(self.context)
                    self.operation_service.start_round(sid, new_rnd)
                    self.output(f"✓ Local active round set to #{new_rnd}.")
                except ValueError:
                    self.output("Invalid round number.")
            elif choice == "2":
                self.operation_service.complete_round(rnd)
                self.output(f"✓ Local round #{rnd} completed.")
            elif choice == "3":
                next_tick = len(ticks) + 1
                tick_val = self._ask("Tick Number", str(next_tick))
                try:
                    t_num = int(tick_val)
                    self.operation_service.record_tick(sid, rnd, t_num)
                    self.output(f"✓ Local tick #{t_num} recorded for round #{rnd}.")
                except ValueError:
                    self.output("Invalid tick number.")

    def _ad_actions(self):
        while True:
            rnd = self.context.current_round if self.context else 0
            actions = self.operation_service.list_actions(round_id=rnd if rnd > 0 else None, limit=20)
            self.output(
                "\nOPERATOR ACTIONS\n"
                "────────────────────────────"
            )
            if not actions:
                self.output("  (no operator actions recorded)")
            else:
                for a in actions:
                    tgt = f" [{a.target_id}]" if a.target_id else ""
                    wf_str = f" [WF: {a.workflow_id[:8]}]" if a.workflow_id else ""
                    parent_str = f" [Parent: {a.parent_action_id[:8]}]" if a.parent_action_id else ""
                    t_str = time.strftime("%H:%M:%S", time.localtime(a.timestamp))
                    self.output(f"  {t_str}  [{a.category.value.upper():<12}] {a.summary}{tgt}{wf_str}{parent_str} ({a.status})")
            self.output(
                "\n  1. Record New Operator Action\n"
                "  0. Back"
            )
            choice = self._ask("Select", "0")
            if choice == "0":
                return
            if choice == "1":
                cat_str = self._ask("Category (recon/attack/defense/flag/verification/system)", "recon").lower()
                try:
                    cat = ActionCategory(cat_str)
                except ValueError:
                    self.output("Invalid category.")
                    continue
                def_tgt = self.context.selected_target if self.context else ""
                tgt = self._ask("Target ID (optional)", def_tgt)
                tool = self._ask("Tool (optional, e.g. manual, nmap, http)", "manual")
                op = self._ask("Operation (e.g. port_scan, config_change)", "action")
                summary = self._ask("Summary")
                if not summary:
                    self.output("Summary is required.")
                    continue
                status = self._ask("Status", "completed")

                wf_id = None
                m_id = None
                wf_choice = self._ask("Attach to workflow? [y/N]", "N").lower()
                if wf_choice in ("y", "yes"):
                    active_wfs = self.operation_service.list_workflows(status=WorkflowStatus.ACTIVE)
                    if active_wfs:
                        self.output("Active workflows:")
                        for w in active_wfs:
                            self.output(f"  [{w.workflow_id[:8]}] {w.title}")
                    wf_input = self._ask("Workflow ID (or prefix)", "").strip()
                    if wf_input:
                        matched = [w for w in active_wfs if w.workflow_id.startswith(wf_input)]
                        wf_id = matched[0].workflow_id if matched else wf_input
                    if wf_id:
                        m_choice = self._ask("Attach to mission? [y/N]", "N").lower()
                        if m_choice in ("y", "yes"):
                            active_ms = self.operation_service.list_missions(workflow_id=wf_id, status=MissionStatus.IN_PROGRESS)
                            if not active_ms:
                                active_ms = self.operation_service.list_missions(workflow_id=wf_id, status=MissionStatus.OPEN)
                            if active_ms:
                                self.output("Available missions:")
                                for m in active_ms:
                                    self.output(f"  [{m.mission_id[:8]}] {m.title} ({m.target_id}:{m.service_port})")
                            m_input = self._ask("Mission ID (or prefix)", "").strip()
                            if m_input:
                                matched = [m for m in active_ms if m.mission_id.startswith(m_input)]
                                m_id = matched[0].mission_id if matched else m_input

                parent_act_id = None
                if cat == ActionCategory.VERIFICATION:
                    p_input = self._ask("Parent Action ID (optional, for verification linking)", "").strip()
                    parent_act_id = p_input or None

                sid = self.context.session_id if self.context else ""
                try:
                    act = self.operation_service.record_action(
                        sid,
                        rnd,
                        cat,
                        tool,
                        op,
                        summary,
                        target_id=tgt or None,
                        status=status,
                        workflow_id=wf_id,
                        mission_id=m_id,
                        parent_action_id=parent_act_id,
                    )
                    wf_str = f" [WF: {act.workflow_id[:8]}]" if act.workflow_id else ""
                    m_str = f" [Mission: {act.mission_id[:8]}]" if act.mission_id else ""
                    self.output(f"✓ Action recorded: [{act.category.value.upper()}]{wf_str}{m_str} {act.summary}")
                except Exception as exc:
                    self.output(f"✗ Failed to record action: {exc}")

    def _ad_attacks(self):
        while True:
            rnd = self.context.current_round if self.context else 0
            attacks = self.operation_service.list_attacks(round_id=rnd if rnd > 0 else None)
            self.output(
                "\nATTACK RECORDS\n"
                "────────────────────────────"
            )
            if not attacks:
                self.output("  (no attack records)")
            else:
                for atk in attacks:
                    self.output(f"  [{atk.id[:8]}] Target: {atk.target_id:<12} Service: {atk.service:<10} Status: {atk.status.value.upper():<10} Method: {atk.method}")
            self.output(
                "\n  1. Record Attack Action\n"
                "  2. Update Attack Status\n"
                "  0. Back"
            )
            choice = self._ask("Select", "0")
            if choice == "0":
                return
            if choice == "1":
                def_tgt = self.context.selected_target if self.context else ""
                tgt = self._ask("Target ID", def_tgt)
                if not tgt:
                    self.output("Target ID is required.")
                    continue
                svc = self._ask("Service (e.g. http/80)", "http/80")
                method = self._ask("Method / Exploit Description")
                if not method:
                    self.output("Method description is required.")
                    continue
                status_str = self._ask("Status (planned/in_progress/success/failed/aborted)", "planned").lower()
                try:
                    st = AttackStatus(status_str)
                except ValueError:
                    st = AttackStatus.PLANNED
                notes = self._ask("Notes (optional)", "")
                try:
                    atk = self.operation_service.record_attack(rnd, tgt, svc, method, status=st, notes=notes)
                    self.output(f"✓ Attack record created: [{atk.id[:8]}] against {tgt} ({st.value.upper()})")
                except Exception as exc:
                    self.output(f"✗ Failed to record attack: {exc}")
            elif choice == "2":
                atk_id = self._ask("Attack ID (prefix or full)")
                found = None
                for a in attacks:
                    if a.id.startswith(atk_id):
                        found = a
                        break
                if not found:
                    self.output("Attack record not found.")
                    continue
                new_st_str = self._ask("New Status (planned/in_progress/success/failed/aborted)", "success").lower()
                try:
                    new_st = AttackStatus(new_st_str)
                except ValueError:
                    self.output("Invalid status.")
                    continue
                notes = self._ask("Notes / Update details", found.notes)
                self.operation_service.update_attack_status(found.id, new_st, notes=notes)
                self.output(f"✓ Attack [{found.id[:8]}] updated to {new_st.value.upper()}.")

    def _ad_defenses(self):
        while True:
            rnd = self.context.current_round if self.context else 0
            defenses = self.operation_service.list_defenses(round_id=rnd if rnd > 0 else None)
            self.output(
                "\nDEFENSE RECORDS\n"
                "────────────────────────────"
            )
            if not defenses:
                self.output("  (no defense records)")
            else:
                for df in defenses:
                    self.output(f"  [{df.id[:8]}] Target: {df.target_id:<12} Service: {df.service:<10} Status: {df.status.value.upper():<10} Action: {df.action}")
            self.output(
                "\n  1. Record Defense Action\n"
                "  2. Update Defense Status\n"
                "  0. Back"
            )
            choice = self._ask("Select", "0")
            if choice == "0":
                return
            if choice == "1":
                def_tgt = self.context.selected_target if self.context else ""
                tgt = self._ask("Target ID", def_tgt)
                if not tgt:
                    self.output("Target ID is required.")
                    continue
                svc = self._ask("Service (e.g. nginx/80)", "nginx/80")
                action = self._ask("Remediation Action (e.g. config change, input validation patch)")
                if not action:
                    self.output("Action description is required.")
                    continue
                status_str = self._ask("Status (planned/in_progress/completed/failed/reverted)", "completed").lower()
                try:
                    st = DefenseStatus(status_str)
                except ValueError:
                    st = DefenseStatus.COMPLETED
                notes = self._ask("Notes (optional)", "")
                try:
                    df = self.operation_service.record_defense(rnd, tgt, svc, action, status=st, notes=notes)
                    self.output(f"✓ Defense record created: [{df.id[:8]}] for {tgt} ({st.value.upper()})")
                except Exception as exc:
                    self.output(f"✗ Failed to record defense: {exc}")
            elif choice == "2":
                df_id = self._ask("Defense ID (prefix or full)")
                found = None
                for d in defenses:
                    if d.id.startswith(df_id):
                        found = d
                        break
                if not found:
                    self.output("Defense record not found.")
                    continue
                new_st_str = self._ask("New Status (planned/in_progress/completed/failed/reverted)", "completed").lower()
                try:
                    new_st = DefenseStatus(new_st_str)
                except ValueError:
                    self.output("Invalid status.")
                    continue
                notes = self._ask("Notes / Update details", found.notes)
                self.operation_service.update_defense_status(found.id, new_st, notes=notes)
                self.output(f"✓ Defense [{found.id[:8]}] updated to {new_st.value.upper()}.")

    def _ad_flags(self):
        while True:
            rnd = self.context.current_round if self.context else 0
            flags = self.operation_service.list_flags(round_id=rnd if rnd > 0 else None)
            self.output(
                "\nFLAG STATE (LOCAL TRACKING)\n"
                "────────────────────────────"
            )
            if not flags:
                self.output("  (no flags recorded)")
            else:
                for fl in flags:
                    t_str = time.strftime("%H:%M:%S", time.localtime(fl.observed_at))
                    self.output(f"  [{fl.id[:8]}] {t_str} Target: {fl.target_id:<12} {fl.flag_preview:<16} Status: {fl.status.value.upper():<10} Source: {fl.source}")
            self.output(
                "\n  1. Record Flag (Fingerprint Only, No Plaintext Stored)\n"
                "  2. Update Flag Status\n"
                "  0. Back"
            )
            choice = self._ask("Select", "0")
            if choice == "0":
                return
            if choice == "1":
                def_tgt = self.context.selected_target if self.context else ""
                tgt = self._ask("Target ID", def_tgt)
                if not tgt:
                    self.output("Target ID is required.")
                    continue
                source = self._ask("Source (e.g. HTTP response, SSH cat, file leak)", "HTTP response")
                raw_flag = self._ask("Flag String (computed to SHA-256 fingerprint; raw text is NOT stored)")
                if not raw_flag:
                    self.output("Flag input is required.")
                    continue
                status_str = self._ask("Status (observed/validated/submitted/rejected/expired)", "validated").lower()
                try:
                    st = FlagStatus(status_str)
                except ValueError:
                    st = FlagStatus.VALIDATED
                notes = self._ask("Notes (optional)", "")
                try:
                    fl = self.operation_service.record_flag(rnd, tgt, source, raw_flag, status=st, notes=notes)
                    self.output(f"✓ Flag recorded: {fl.flag_preview} [{fl.fingerprint[:16]}...] Status: {fl.status.value.upper()}")
                except Exception as exc:
                    self.output(f"✗ Failed to record flag: {exc}")
            elif choice == "2":
                fl_id = self._ask("Flag ID (prefix or full)")
                found = None
                for f in flags:
                    if f.id.startswith(fl_id):
                        found = f
                        break
                if not found:
                    self.output("Flag record not found.")
                    continue
                new_st_str = self._ask("New Status (observed/validated/submitted/rejected/expired)", "submitted").lower()
                try:
                    new_st = FlagStatus(new_st_str)
                except ValueError:
                    self.output("Invalid status.")
                    continue
                notes = self._ask("Notes / Update details", found.notes)
                self.operation_service.update_flag_status(found.id, new_st, notes=notes)
                self.output(f"✓ Flag [{found.id[:8]}] updated to {new_st.value.upper()}.")

    def _ad_sla(self):
        while True:
            rnd = self.context.current_round if self.context else 0
            sla_list = self.operation_service.list_sla(round_id=rnd if rnd > 0 else None, limit=20)
            self.output(
                "\nSLA / HEALTH (LOCAL OBSERVATIONS)\n"
                "────────────────────────────\n"
                "Notice: Local observations - not official platform checker\n"
            )
            if not sla_list:
                self.output("  (no local SLA observations recorded)")
            else:
                for s in sla_list:
                    lat = f"{s.latency_ms:.0f}ms" if s.latency_ms is not None else "n/a"
                    t_str = time.strftime("%H:%M:%S", time.localtime(s.observed_at))
                    self.output(f"  {t_str} Target: {s.target_id:<12} Service: {s.service:<10} Status: {s.status.value.upper():<8} Latency: {lat:<6} ({s.source})")
            self.output(
                "\n  1. Record Local SLA Observation\n"
                "  0. Back"
            )
            choice = self._ask("Select", "0")
            if choice == "0":
                return
            if choice == "1":
                def_tgt = self.context.selected_target if self.context else ""
                tgt = self._ask("Target ID", def_tgt)
                if not tgt:
                    self.output("Target ID is required.")
                    continue
                svc = self._ask("Service (e.g. http/80, ssh/22)", "http/80")
                st_str = self._ask("Status (ok/mumble/offline/unknown)", "ok").lower()
                try:
                    st = SlaStatus(st_str)
                except ValueError:
                    st = SlaStatus.OK
                lat_str = self._ask("Observed Latency in ms (optional)", "")
                lat = float(lat_str) if lat_str else None
                source = self._ask("Observation Source", "local")
                try:
                    obs = self.operation_service.record_sla(rnd, tgt, svc, st, latency_ms=lat, source=source)
                    self.output(f"✓ SLA observation recorded: {tgt} {svc} -> {obs.status.value.upper()}")
                except Exception as exc:
                    self.output(f"✗ Failed to record SLA observation: {exc}")

    def _ad_timeline(self):
        rnd = self.context.current_round if self.context else 0
        timeline = self.operation_service.get_timeline(round_id=rnd if rnd > 0 else None, limit=40)
        self.output(
            "\nACTIVITY TIMELINE\n"
            "────────────────────────────"
        )
        if not timeline:
            self.output("  (no activity recorded yet)")
        else:
            for entry in timeline:
                t_str = time.strftime("%H:%M:%S", time.localtime(entry.timestamp))
                tgt = f"{entry.target_id:<14}" if entry.target_id else " " * 14
                self.output(f"  {t_str}  {entry.category:<12} {tgt} {entry.title:<30} {entry.status}")
        self.output("")
        self._ask("Press Enter to return", "")

    def _ad_workflows(self):
        while True:
            self.output(
                "\nOPERATOR WORKFLOWS\n"
                "────────────────────────────\n"
                "  1. List Workflows\n"
                "  2. Start Workflow\n"
                "  3. Open Workflow\n"
                "  4. Complete Workflow\n"
                "  5. Abort Workflow\n"
                "  6. Workflow Timeline\n"
                "  0. Back"
            )
            choice = self._ask("Select", "0")
            if choice == "0":
                return
            elif choice == "1":
                self._list_workflows_ui()
            elif choice == "2":
                self._start_workflow_ui()
            elif choice == "3":
                self._open_workflow_ui()
            elif choice == "4":
                self._complete_workflow_ui()
            elif choice == "5":
                self._abort_workflow_ui()
            elif choice == "6":
                self._workflow_timeline_ui()
            else:
                self.output("Invalid selection.")

    def _list_workflows_ui(self):
        wfs = self.operation_service.list_workflows()
        self.output("\nWORKFLOW LIST\n────────────────────────────")
        if not wfs:
            self.output("  (no workflows recorded)")
        else:
            for w in wfs:
                tgt = f" [{w.target_id}]" if w.target_id else ""
                t_str = time.strftime("%H:%M:%S", time.localtime(w.started_at))
                self.output(f"  [{w.workflow_id[:8]}] {t_str}  {w.status.value.upper():<10} R#{w.round_id}{tgt}  {w.title}")
        self.output("")
        self._ask("Press Enter to continue", "")

    def _start_workflow_ui(self):
        title = self._ask("Workflow Title")
        if not title:
            self.output("Workflow title is required.")
            return
        objective = self._ask("Objective (optional)", "")
        def_tgt = self.context.selected_target if self.context else ""
        tgt = self._ask("Target ID (optional)", def_tgt)
        notes = self._ask("Notes (optional)", "")
        sid = self.context.session_id if self.context else "default-session"
        cur_rnd = self.context.current_round if self.context else 1
        try:
            if not self.operation_service.get_session(sid):
                self.operation_service.create_session(
                    session_id=sid,
                    operator=self.context.operator_name if self.context else "Operator",
                    platform=self.context.platform if self.context else "jjz.jatimprov.go.id",
                )
            if not self.operation_service.get_round(cur_rnd):
                self.operation_service.start_round(sid, cur_rnd)

            wf = self.operation_service.create_workflow(
                session_id=sid,
                round_id=cur_rnd,
                title=title,
                objective=objective,
                target_id=tgt or None,
                notes=notes,
            )
            self.output(f"✓ Workflow started: [{wf.workflow_id[:8]}] {wf.title} (Status: {wf.status.value.upper()})")
        except Exception as exc:
            self.output(f"✗ Failed to start workflow: {exc}")

    def _open_workflow_ui(self):
        wf_id_input = self._ask("Workflow ID (or prefix)").strip()
        if not wf_id_input:
            return
        wfs = self.operation_service.list_workflows()
        matched = [w for w in wfs if w.workflow_id.startswith(wf_id_input)]
        if not matched:
            self.output(f"Workflow not found: {wf_id_input}")
            return
        wf = matched[0]
        self.output(
            f"\nWORKFLOW #{wf.workflow_id[:8]}\n"
            "────────────────────────────\n"
            f"  Title:        {wf.title}\n"
            f"  Objective:    {wf.objective or '-'}\n"
            f"  Target:       {wf.target_id or '-'}\n"
            f"  Round:        Round #{wf.round_id}\n"
            f"  Status:       {wf.status.value.upper()}\n"
            f"  Started:      {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(wf.started_at))}\n"
            f"  Completed:    {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(wf.completed_at)) if wf.completed_at else '-'}\n"
            f"  Notes:        {wf.notes or '-'}"
        )

        # Intelligence Correlation (Target -> Current Intelligence -> Historical Observations -> Workflow Activity)
        if wf.target_id and self.target_service:
            tgt = self.target_service.get_target(wf.target_id)
            if tgt:
                self.output("\n  TARGET INTELLIGENCE CORRELATION:")
                self.output(f"    Target:      {tgt.id} ({tgt.host}) Role: {tgt.role.value}")
                obs_list = self.target_service.history(tgt.id)
                self.output(f"    Historical:  {len(obs_list)} observation(s)")
                if obs_list:
                    latest = obs_list[0]
                    t_str = time.strftime("%H:%M:%S", time.localtime(latest.observed_at))
                    srvs = ", ".join(f"{s.port}/{s.name}" for s in latest.services) if latest.services else "none"
                    self.output(f"    Latest Obs:  #{latest.id} at {t_str} Status: {latest.status} (Services: {srvs})")

        # Workflow Activity
        entries = self.operation_service.get_workflow_timeline(wf.workflow_id)
        self.output(f"\n  CORRELATED WORKFLOW ACTIVITY ({len(entries)} events):")
        if not entries:
            self.output("    (no operational actions associated with this workflow)")
        else:
            for e in entries:
                t_str = time.strftime("%H:%M:%S", time.localtime(e.timestamp))
                self.output(f"    {t_str}  [{e.category:<12}] {e.title} [{e.status}]")

        self.output("")
        self._ask("Press Enter to continue", "")

    def _complete_workflow_ui(self):
        wf_id_input = self._ask("Workflow ID (or prefix)").strip()
        if not wf_id_input:
            return
        wfs = self.operation_service.list_workflows(status=WorkflowStatus.ACTIVE)
        matched = [w for w in wfs if w.workflow_id.startswith(wf_id_input)]
        if not matched:
            self.output(f"Active workflow not found: {wf_id_input}")
            return
        wf = matched[0]
        notes = self._ask("Closing notes (optional)", wf.notes)
        try:
            self.operation_service.complete_workflow(wf.workflow_id, notes=notes or None)
            self.output(f"✓ Workflow [{wf.workflow_id[:8]}] completed.")
        except Exception as exc:
            self.output(f"✗ Failed to complete workflow: {exc}")

    def _abort_workflow_ui(self):
        wf_id_input = self._ask("Workflow ID (or prefix)").strip()
        if not wf_id_input:
            return
        wfs = self.operation_service.list_workflows(status=WorkflowStatus.ACTIVE)
        matched = [w for w in wfs if w.workflow_id.startswith(wf_id_input)]
        if not matched:
            self.output(f"Active workflow not found: {wf_id_input}")
            return
        wf = matched[0]
        notes = self._ask("Abort reason / notes (optional)", wf.notes)
        try:
            self.operation_service.abort_workflow(wf.workflow_id, notes=notes or None)
            self.output(f"✓ Workflow [{wf.workflow_id[:8]}] aborted.")
        except Exception as exc:
            self.output(f"✗ Failed to abort workflow: {exc}")

    def _workflow_timeline_ui(self):
        wf_id_input = self._ask("Workflow ID (or prefix)").strip()
        if not wf_id_input:
            return
        wfs = self.operation_service.list_workflows()
        matched = [w for w in wfs if w.workflow_id.startswith(wf_id_input)]
        if not matched:
            self.output(f"Workflow not found: {wf_id_input}")
            return
        wf = matched[0]
        entries = self.operation_service.get_workflow_timeline(wf.workflow_id)
        self.output(f"\nWORKFLOW #{wf.workflow_id[:8]}")
        self.output(f"{wf.title}")
        self.output(f"Status: {wf.status.value.upper()}\n")
        if not entries:
            self.output("  (no activity recorded for this workflow)")
        else:
            self.output(f"  {'TIME':<10} {'CATEGORY':<14} {'EVENT'}")
            for e in entries:
                t_str = time.strftime("%H:%M:%S", time.localtime(e.timestamp))
                self.output(f"  {t_str:<10} {e.category:<14} {e.title}")
        self.output("")
        self._ask("Press Enter to continue", "")

    # --- MISSIONS UI ---

    def _ad_missions(self):
        while True:
            self.output(
                "\nMISSIONS\n"
                "────────────────────────────\n"
                "  1. List Missions\n"
                "  2. Create Mission\n"
                "  3. Open Mission\n"
                "  4. Start Mission\n"
                "  5. Complete Mission\n"
                "  6. Abort Mission\n"
                "  7. Mission Timeline\n"
                "  0. Back"
            )
            choice = self._ask("Select", "0")
            if choice == "0":
                return
            elif choice == "1":
                self._list_missions_ui()
            elif choice == "2":
                self._create_mission_ui()
            elif choice == "3":
                self._open_mission_ui()
            elif choice == "4":
                self._start_mission_ui()
            elif choice == "5":
                self._complete_mission_ui()
            elif choice == "6":
                self._abort_mission_ui()
            elif choice == "7":
                self._mission_timeline_ui()
            else:
                self.output("Invalid selection.")

    def _list_missions_ui(self):
        missions = self.operation_service.list_missions()
        self.output("\nMISSIONS\n────────────────────────────")
        if not missions:
            self.output("  (no missions created)")
        else:
            for m in missions:
                t_str = time.strftime("%H:%M:%S", time.localtime(m.created_at))
                srv = f"{m.service_protocol.upper()}:{m.service_port}"
                self.output(f"  [{m.mission_id[:8]}] {m.title} (Target: {m.target_id}, {srv}) [{m.status.value.upper()}] @ {t_str}")
        self.output("")

    def _create_mission_ui(self):
        active_wfs = self.operation_service.list_workflows(status=WorkflowStatus.ACTIVE)
        if not active_wfs:
            active_wfs = self.operation_service.list_workflows()
        if not active_wfs:
            self.output("No workflows found. Create a workflow first.")
            return

        self.output("Available Workflows:")
        for w in active_wfs:
            self.output(f"  [{w.workflow_id[:8]}] {w.title} (Target: {w.target_id or 'none'}) [{w.status.value.upper()}]")

        wf_input = self._ask("Workflow ID (or prefix)").strip()
        if not wf_input:
            return
        matched = [w for w in active_wfs if w.workflow_id.startswith(wf_input)]
        if not matched:
            self.output(f"Workflow not found: {wf_input}")
            return
        wf = matched[0]

        def_tgt = wf.target_id or (self.context.selected_target if self.context else "")
        target_id = self._ask("Target ID", def_tgt).strip()
        if not target_id:
            self.output("Target ID is required.")
            return

        port_str = self._ask("Service Port (e.g. 80, 8080, 22)").strip()
        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError("port out of range")
        except ValueError:
            self.output("Invalid service port (must be 1-65535).")
            return

        protocol = self._ask("Protocol (tcp/udp)", "tcp").strip().lower()
        title = self._ask("Mission Title").strip()
        if not title:
            self.output("Title is required.")
            return
        objective = self._ask("Mission Objective (optional)").strip()

        init_obs_id = None
        if self.target_service:
            hist = self.target_service.history(target_id, limit=5)
            if hist:
                self.output("Target Observations:")
                for o in hist:
                    t_str = time.strftime("%H:%M:%S", time.localtime(o.observed_at))
                    srvs = ", ".join(f"{s.port}/{s.name}" for s in o.services) if o.services else "none"
                    self.output(f"  #{o.id} at {t_str} [{o.status}] (services: {srvs})")
                obs_choice = self._ask("Initial Observation ID (optional, Enter to skip)", "").strip()
                if obs_choice:
                    try:
                        init_obs_id = int(obs_choice)
                    except ValueError:
                        self.output("Invalid observation ID, skipping association.")

        notes = self._ask("Notes (optional)").strip()

        try:
            m = self.operation_service.create_mission(
                workflow_id=wf.workflow_id,
                target_id=target_id,
                service_port=port,
                service_protocol=protocol,
                title=title,
                objective=objective,
                notes=notes,
                initial_observation_id=init_obs_id,
            )
            self.output(f"✓ Mission created: [{m.mission_id[:8]}] {m.title} (Status: {m.status.value.upper()})")
            open_cockpit = self._ask("Open mission cockpit now? [Y/n]", "Y").strip().lower()
            if open_cockpit in ("", "y", "yes"):
                self._mission_cockpit(m)
        except Exception as exc:
            self.output(f"✗ Failed to create mission: {exc}")

    def _open_mission_ui(self):
        m_id_input = self._ask("Mission ID (or prefix)").strip()
        if not m_id_input:
            return
        missions = self.operation_service.list_missions()
        matched = [m for m in missions if m.mission_id.startswith(m_id_input)]
        if not matched:
            self.output(f"Mission not found: {m_id_input}")
            return
        self._mission_cockpit(matched[0])

    def _start_mission_ui(self):
        m_id_input = self._ask("Mission ID (or prefix)").strip()
        if not m_id_input:
            return
        missions = self.operation_service.list_missions()
        matched = [m for m in missions if m.mission_id.startswith(m_id_input)]
        if not matched:
            self.output(f"Mission not found: {m_id_input}")
            return
        m = matched[0]
        try:
            self.operation_service.start_mission(m.mission_id)
            self.output(f"✓ Mission [{m.mission_id[:8]}] started (IN_PROGRESS).")
        except Exception as exc:
            self.output(f"✗ Failed to start mission: {exc}")

    def _complete_mission_ui(self):
        m_id_input = self._ask("Mission ID (or prefix)").strip()
        if not m_id_input:
            return
        missions = self.operation_service.list_missions()
        matched = [m for m in missions if m.mission_id.startswith(m_id_input)]
        if not matched:
            self.output(f"Mission not found: {m_id_input}")
            return
        m = matched[0]
        notes = self._ask("Closing notes (optional)", m.notes)
        try:
            self.operation_service.complete_mission(m.mission_id, notes=notes or None)
            self.output(f"✓ Mission [{m.mission_id[:8]}] completed.")
        except Exception as exc:
            self.output(f"✗ Failed to complete mission: {exc}")

    def _abort_mission_ui(self):
        m_id_input = self._ask("Mission ID (or prefix)").strip()
        if not m_id_input:
            return
        missions = self.operation_service.list_missions()
        matched = [m for m in missions if m.mission_id.startswith(m_id_input)]
        if not matched:
            self.output(f"Mission not found: {m_id_input}")
            return
        m = matched[0]
        notes = self._ask("Abort reason / notes (optional)", m.notes)
        try:
            self.operation_service.abort_mission(m.mission_id, notes=notes or None)
            self.output(f"✓ Mission [{m.mission_id[:8]}] aborted.")
        except Exception as exc:
            self.output(f"✗ Failed to abort mission: {exc}")

    def _mission_timeline_ui(self):
        m_id_input = self._ask("Mission ID (or prefix)").strip()
        if not m_id_input:
            return
        missions = self.operation_service.list_missions()
        matched = [m for m in missions if m.mission_id.startswith(m_id_input)]
        if not matched:
            self.output(f"Mission not found: {m_id_input}")
            return
        m = matched[0]
        entries = self.operation_service.get_mission_timeline(m.mission_id)
        self.output(f"\nMISSION #{m.mission_id[:8]}")
        self.output(f"Title:   {m.title}")
        self.output(f"Target:  {m.target_id} ({m.service_protocol.upper()}/{m.service_port})")
        self.output(f"Status:  {m.status.value.upper()}\n")
        if not entries:
            self.output("  (no activity recorded for this mission)")
        else:
            self.output(f"  {'TIME':<10} {'CATEGORY':<14} {'EVENT'}")
            for e in entries:
                t_str = time.strftime("%H:%M:%S", time.localtime(e.timestamp))
                self.output(f"  {t_str:<10} {e.category:<14} {e.title}")
        self.output("")
        self._ask("Press Enter to continue", "")

    def _mission_cockpit(self, m: Mission):
        while True:
            # Refresh from database
            fresh = self.operation_service.get_mission(m.mission_id)
            if fresh:
                m = fresh

            tgt = self.target_service.get_target(m.target_id) if self.target_service else None
            tgt_host = f" ({tgt.host})" if tgt else ""

            self.output(
                f"\nMISSION #{m.mission_id[:8]}\n"
                "────────────────────────────────────\n"
                f"{m.title}\n"
                f"Target:   {m.target_id}{tgt_host}\n"
                f"Service:  {m.service_protocol.upper()}/{m.service_port}\n"
                f"Status:   {m.status.value.upper()}\n\n"
                "OBJECTIVE\n"
                f"{m.objective or '-'}\n"
            )

            # Target Intelligence
            latest_obs = None
            if self.target_service:
                history = self.target_service.history(m.target_id, limit=10)
                if history:
                    latest_obs = history[0]
                    srvs = ", ".join(f"{s.port}/{s.name}" for s in latest_obs.services) if latest_obs.services else "none"
                    t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(latest_obs.observed_at))
                    self.output(
                        "CURRENT INTELLIGENCE\n"
                        f"Observation: #{latest_obs.id}\n"
                        f"Services:    {srvs}\n"
                        f"Status:      {latest_obs.status}\n"
                        f"Observed:    {t_str}\n"
                    )
                else:
                    self.output("CURRENT INTELLIGENCE\nNo observations recorded for target.\n")

            # Recent Activity
            entries = self.operation_service.get_mission_timeline(m.mission_id)
            self.output("RECENT ACTIVITY")
            if not entries:
                self.output("  (no activity recorded for this mission)")
            else:
                for e in entries[-5:]:
                    t_str = time.strftime("%H:%M:%S", time.localtime(e.timestamp))
                    self.output(f"  {t_str}  [{e.category:<12}] {e.title} [{e.status}]")
            self.output("")

            # Flags
            flags = self.operation_service.list_flags(mission_id=m.mission_id)
            obs_cnt = len(flags)
            sub_cnt = sum(1 for f in flags if f.status == FlagStatus.SUBMITTED)
            self.output(f"FLAGS\n  {obs_cnt} observed\n  {sub_cnt} submitted\n")

            # Health
            slas = self.operation_service.list_sla(mission_id=m.mission_id, limit=1)
            last_sla = slas[0].status.value.upper() if slas else "No checks recorded"
            self.output(f"HEALTH\n  Last local check: {last_sla}\n")

            self.output(
                "ACTIONS\n"
                "  1. Record Action\n"
                "  2. Record Attack\n"
                "  3. Record Defense\n"
                "  4. Record Flag\n"
                "  5. Record Verification\n"
                "  6. Run Tool\n"
                "  7. Refresh Intelligence\n"
                "  8. Compare Observations\n"
                "  9. Complete Mission\n"
                "  10. Abort Mission\n"
                "  0. Back"
            )

            choice = self._ask("Select", "0")
            if choice == "0":
                return
            elif choice == "1":
                self._cockpit_record_action(m)
            elif choice == "2":
                self._cockpit_record_attack(m)
            elif choice == "3":
                self._cockpit_record_defense(m)
            elif choice == "4":
                self._cockpit_record_flag(m)
            elif choice == "5":
                self._cockpit_record_verification(m)
            elif choice == "6":
                self._cockpit_run_tool(m)
            elif choice == "7":
                self._cockpit_refresh_intelligence(m)
            elif choice == "8":
                self._cockpit_compare_observations(m)
            elif choice == "9":
                notes = self._ask("Closing notes (optional)", m.notes)
                try:
                    self.operation_service.complete_mission(m.mission_id, notes=notes or None)
                    self.output("✓ Mission completed.")
                except Exception as exc:
                    self.output(f"✗ Failed to complete mission: {exc}")
            elif choice == "10":
                notes = self._ask("Abort reason / notes (optional)", m.notes)
                try:
                    self.operation_service.abort_mission(m.mission_id, notes=notes or None)
                    self.output("✓ Mission aborted.")
                except Exception as exc:
                    self.output(f"✗ Failed to abort mission: {exc}")
            else:
                self.output("Invalid selection.")

    def _cockpit_record_action(self, m: Mission):
        cat_str = self._ask("Category (recon/attack/defense/flag/verification/system)", "recon").lower()
        try:
            cat = ActionCategory(cat_str)
        except ValueError:
            self.output("Invalid category.")
            return
        tool = self._ask("Tool (e.g. manual, nmap, http)", "manual")
        op = self._ask("Operation", "action")
        summary = self._ask("Summary")
        if not summary:
            self.output("Summary is required.")
            return
        status = self._ask("Status", "completed")
        parent_act_id = None
        if cat == ActionCategory.VERIFICATION:
            p_input = self._ask("Parent Action ID (optional)", "").strip()
            parent_act_id = p_input or None

        sid = self.context.session_id if self.context else ""
        rnd = self.context.current_round if self.context else 0
        try:
            act = self.operation_service.record_action(
                sid,
                rnd,
                cat,
                tool,
                op,
                summary,
                target_id=m.target_id,
                status=status,
                workflow_id=m.workflow_id,
                mission_id=m.mission_id,
                parent_action_id=parent_act_id,
            )
            self.output(f"✓ Action recorded: [{act.category.value.upper()}] {act.summary}")
        except Exception as exc:
            self.output(f"✗ Failed to record action: {exc}")

    def _cockpit_record_attack(self, m: Mission):
        technique = self._ask("Attack Technique / Exploit Name")
        if not technique:
            self.output("Technique is required.")
            return
        status_str = self._ask("Status (planned/in_progress/success/failed/aborted)", "success").lower()
        try:
            status = AttackStatus(status_str)
        except ValueError:
            status = AttackStatus.SUCCESS
        notes = self._ask("Notes (optional)")

        rnd = self.context.current_round if self.context else 0
        try:
            atk = self.operation_service.record_attack(
                rnd,
                m.target_id,
                f"{m.service_protocol}/{m.service_port}",
                technique,
                status=status,
                workflow_id=m.workflow_id,
                mission_id=m.mission_id,
                notes=notes,
            )
            self.output(f"✓ Attack recorded: [{atk.status.value.upper()}] {atk.method} on {atk.target_id} ({atk.service})")
        except Exception as exc:
            self.output(f"✗ Failed to record attack: {exc}")

    def _cockpit_record_defense(self, m: Mission):
        patch_type = self._ask("Patch / Defense Action (e.g. config_change, firewall, code_fix)", "patch")
        status_str = self._ask("Status (planned/in_progress/completed/failed/reverted)", "completed").lower()
        try:
            status = DefenseStatus(status_str)
        except ValueError:
            status = DefenseStatus.COMPLETED
        notes = self._ask("Notes (optional)")

        rnd = self.context.current_round if self.context else 0
        try:
            defn = self.operation_service.record_defense(
                rnd,
                m.target_id,
                f"{m.service_protocol}/{m.service_port}",
                patch_type,
                status=status,
                workflow_id=m.workflow_id,
                mission_id=m.mission_id,
                notes=notes,
            )
            self.output(f"✓ Defense recorded: [{defn.status.value.upper()}] {defn.action} on {defn.target_id}")
        except Exception as exc:
            self.output(f"✗ Failed to record defense: {exc}")

    def _cockpit_record_flag(self, m: Mission):
        flag_raw = self._ask("Raw Flag (will be hashed, plaintext NEVER stored)")
        if not flag_raw.strip():
            self.output("Flag cannot be empty.")
            return
        status_str = self._ask("Status (observed/validated/submitted/rejected/expired)", "validated").lower()
        try:
            status = FlagStatus(status_str)
        except ValueError:
            status = FlagStatus.VALIDATED
        notes = self._ask("Notes (optional)")

        rnd = self.context.current_round if self.context else 0
        try:
            flg = self.operation_service.record_flag(
                rnd,
                m.target_id,
                "manual",
                flag_raw,
                status=status,
                workflow_id=m.workflow_id,
                mission_id=m.mission_id,
                notes=notes,
            )
            self.output(f"✓ Flag recorded: {flg.flag_preview} (Hash: {flg.fingerprint[:16]}..., Status: {flg.status.value.upper()})")
        except Exception as exc:
            self.output(f"✗ Failed to record flag: {exc}")

    def _cockpit_record_verification(self, m: Mission):
        actions = self.operation_service.list_actions(mission_id=m.mission_id, limit=10)
        parent_act_id = None
        if actions:
            self.output("\nMission Actions for Parent Linking:")
            for a in actions:
                self.output(f"  [{a.id[:8]}] [{a.category.value.upper()}] {a.summary}")
            p_in = self._ask("Select Parent Action ID (or prefix, Enter to skip)", "").strip()
            if p_in:
                matched = [a for a in actions if a.id.startswith(p_in)]
                parent_act_id = matched[0].id if matched else p_in

        tool = self._ask("Verification Tool (e.g. http, nmap, manual)", "manual")
        summary = self._ask("Verification Summary", "Service verification check")
        status = self._ask("Verification Result (verified/failed)", "verified")

        sid = self.context.session_id if self.context else ""
        rnd = self.context.current_round if self.context else 0
        try:
            act = self.operation_service.record_action(
                sid,
                rnd,
                ActionCategory.VERIFICATION,
                tool,
                "verification",
                summary,
                target_id=m.target_id,
                status=status,
                workflow_id=m.workflow_id,
                mission_id=m.mission_id,
                parent_action_id=parent_act_id,
            )
            self.output(f"✓ Verification action recorded: [{act.id[:8]}] {act.summary}")
        except Exception as exc:
            self.output(f"✗ Failed to record verification action: {exc}")

        # Optional SLA observation
        sla_choice = self._ask("Record SLA / health observation for this service? [y/N]", "N").strip().lower()
        if sla_choice in ("y", "yes"):
            s_stat_str = self._ask("SLA Status (ok/mumble/offline)", "ok").lower()
            try:
                s_stat = SlaStatus(s_stat_str)
            except ValueError:
                s_stat = SlaStatus.OK
            lat_str = self._ask("Latency ms (optional)", "0")
            try:
                lat = float(lat_str)
            except ValueError:
                lat = None
            notes = self._ask("Notes (optional)", "")
            try:
                sla = self.operation_service.record_sla(
                    rnd,
                    m.target_id,
                    f"{m.service_protocol}/{m.service_port}",
                    s_stat,
                    latency_ms=lat,
                    workflow_id=m.workflow_id,
                    mission_id=m.mission_id,
                    details={"notes": notes} if notes else {},
                )
                self.output(f"✓ SLA observation recorded: [{sla.status.value.upper()}] for {sla.service}")
            except Exception as exc:
                self.output(f"✗ Failed to record SLA: {exc}")

        # Optional intelligence refresh
        intel_choice = self._ask("Run new intelligence scan now? [y/N]", "N").strip().lower()
        if intel_choice in ("y", "yes"):
            self._cockpit_refresh_intelligence(m)

    def _cockpit_run_tool(self, m: Mission):
        self.output(
            "\nRUN OPERATOR TOOL\n"
            "────────────────────────────\n"
            f"  1. Nmap port scan (port {m.service_port})\n"
            f"  2. HTTP check (GET on port {m.service_port})\n"
            "  3. Open Tool Menu\n"
            "  0. Cancel"
        )
        choice = self._ask("Select", "0")
        if choice == "0":
            return
        elif choice == "1":
            tgt = self.target_service.get_target(m.target_id) if self.target_service else None
            host = tgt.host if tgt else m.target_id
            if self.scope and not self.scope.is_allowed(host):
                self.output(f"✗ Scope rejection: host '{host}' is outside authorized scope.")
                return
            try:
                res, services = self.nmap_service.scan_target_detailed(host, ports=[m.service_port])
                if res.success:
                    srv_lines = "\n".join(f"  {s.port}/{s.protocol:<4} {s.name:<12} {s.version}".rstrip() for s in services) or "  (none open)"
                    self._present_success("Nmap", host, res.duration_s, f"Open Services:\n{srv_lines}")
                else:
                    self._present_failure("Nmap", host, res.duration_s, res.error_kind or "nonzero_exit", res.stderr or res.error or "")

                rec_choice = self._ask(f"Record as action under Mission #{m.mission_id[:8]}? [y/N]", "N").lower()
                if rec_choice in ("y", "yes"):
                    cat_str = self._ask("Category (recon/verification/attack/defense)", "recon").lower()
                    try:
                        cat = ActionCategory(cat_str)
                    except ValueError:
                        cat = ActionCategory.RECON
                    sum_str = self._ask("Summary", f"Nmap scan port {m.service_port} on {host}")
                    sid = self.context.session_id if self.context else ""
                    rnd = self.context.current_round if self.context else 0
                    self.operation_service.record_action(
                        sid, rnd, cat, "nmap", "scan", sum_str,
                        target_id=m.target_id,
                        status="completed" if res.success else "failed",
                        workflow_id=m.workflow_id,
                        mission_id=m.mission_id,
                        details={"ports": [m.service_port], "duration_s": res.duration_s},
                    )
                    self.output("✓ Action recorded under mission.")
            except Exception as exc:
                self.output(f"✗ Tool execution failed: {exc}")
        elif choice == "2":
            tgt = self.target_service.get_target(m.target_id) if self.target_service else None
            host = tgt.host if tgt else m.target_id
            url = f"http://{host}:{m.service_port}/"
            if self.scope and not self.scope.is_allowed(host):
                self.output(f"✗ Scope rejection: host '{host}' is outside authorized scope.")
                return
            try:
                res, resp = self.http_service.adapter.execute(
                    HttpRequest(url=url, method="GET", timeout_s=5.0)
                )
                if resp.status_code > 0:
                    self._present_success("HTTP", url, res.duration_s, f"Status: {resp.status_code} {resp.reason}\nBody:\n{resp.body[:500]}")
                else:
                    self._present_failure("HTTP", url, res.duration_s, res.error_kind or "nonzero_exit", res.stderr or res.error or "")

                rec_choice = self._ask(f"Record as action under Mission #{m.mission_id[:8]}? [y/N]", "N").lower()
                if rec_choice in ("y", "yes"):
                    cat_str = self._ask("Category (recon/verification/attack/defense)", "verification").lower()
                    try:
                        cat = ActionCategory(cat_str)
                    except ValueError:
                        cat = ActionCategory.VERIFICATION
                    sum_str = self._ask("Summary", f"HTTP GET {url} -> {resp.status_code}")
                    sid = self.context.session_id if self.context else ""
                    rnd = self.context.current_round if self.context else 0
                    self.operation_service.record_action(
                        sid, rnd, cat, "http", "get", sum_str,
                        target_id=m.target_id,
                        status="completed" if res.success else "failed",
                        workflow_id=m.workflow_id,
                        mission_id=m.mission_id,
                        details={"url": url, "status_code": resp.status_code, "duration_s": res.duration_s},
                    )
                    self.output("✓ Action recorded under mission.")
            except Exception as exc:
                self.output(f"✗ HTTP execution failed: {exc}")
        elif choice == "3":
            self._tools_menu()

    def _cockpit_refresh_intelligence(self, m: Mission):
        if self.recon_service is None or self.scope is None:
            self.output("Scan is not configured (missing recon_service or scope).")
            return
        tgt = self.target_service.get_target(m.target_id) if self.target_service else None
        if not tgt:
            self.output(f"Target not found: {m.target_id}")
            return
        try:
            obs = self.recon_service.scan_target(
                tgt,
                self.scope,
                ports=[m.service_port],
                session_id=self.context.session_id if self.context else "",
                round_id=self.context.current_round if self.context else 0,
            )
            self._show_observation(obs)
            history = self.target_service.history(tgt.id)
            if len(history) > 1:
                intel = diff_history(history)
                self.output(
                    f"Changes since observation #{intel.previous_id}:\n{intel.render()}"
                    if intel and intel.entries
                    else "No intelligence changes since the previous observation."
                )
            else:
                self.output("First observation recorded for this target.")
        except ValueError as exc:
            self.output(f"Scope/Target rejection: {exc}")
        except Exception as exc:
            self.output(f"Scan failed: {exc}")

    def _cockpit_compare_observations(self, m: Mission):
        if not self.target_service:
            self.output("Target service not configured.")
            return
        history = self.target_service.history(m.target_id)
        if not history:
            self.output("No observations found for this target.")
            return
        if len(history) < 2:
            self.output(f"Only {len(history)} observation(s) available. Need at least 2 to compare.")
            return
        self.output("Observations:\n" + "\n".join(f"  #{o.id}  round={o.round_id}  status={o.status}" for o in history))
        try:
            older_id = int(self._ask("Older observation ID"))
            newer_id = int(self._ask("Newer observation ID"))
        except ValueError:
            self.output("Invalid observation ID.")
            return
        observations = {o.id: o for o in history}
        if older_id not in observations or newer_id not in observations:
            self.output("Observation not found in target history.")
            return
        self.output(compare_observations(observations[older_id], observations[newer_id]).render())

    def _ad_knowledge(self):
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
