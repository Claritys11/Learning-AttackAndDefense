from __future__ import annotations
import os

from ..context import ContextStore, OperatorContext
from ..integrations import ReconService
from ..integrations.tool_runner import ToolRunner
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
    ):
        self.store = store
        self.input = input_fn
        self.output = output_fn
        self.context = store.load()
        self.target_service = TargetService(store.path)
        self.recon_service = recon_service
        self.scope = scope

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

    def _tools_menu(self):
        while True:
            self.output(
                "OPERATOR TOOLS\n"
                "  1. Nmap (Discovery & Port Scan)\n"
                "  2. HTTP / Curl (Request Inspector)\n"
                "  3. ffuf (Endpoint Discovery)\n"
                "  4. SSH (Team VM Execution)\n"
                "  5. tcpdump (Packet Capture)\n"
                "  6. GDB (Binary Analysis)\n"
                "  7. System Diagnostics (ss / ps / systemctl / ip / wg)\n"
                "  0. Back"
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
        self.output("NMAP\n  1. Host Discovery (-sn)\n  2. Port Scan (-p)\n  3. Service Scan (-sV -sC)\n  0. Back")
        mode = self._ask("Select", "0")
        if mode == "0":
            return
        if mode == "1":
            network = self._ask("Network CIDR", self.context.enemy_subnet or "10.0.0.0/24")
            try:
                hosts = self.nmap_service.discover(network)
                self.output(f"Discovered {len(hosts)} hosts:")
                for h in hosts:
                    self.output(f"  {h.host} ({h.status})")
            except Exception as exc:
                self.output(f"Nmap discovery failed: {exc}")
        elif mode in {"2", "3"}:
            def_host = ""
            if self.context.selected_target:
                t = self.target_service.get_target(self.context.selected_target)
                if t:
                    def_host = t.host
            host = self._ask("Target Host / IP", def_host)
            ports = self._ask("Port Range", "1-1024")
            try:
                services = self.nmap_service.scan_target(host, ports=ports, service_detection=(mode == "3"))
                self.output(f"Open services on {host}:")
                for s in services:
                    self.output(f"  {s.port}/{s.protocol}  {s.name}  {s.version}".rstrip())
            except Exception as exc:
                self.output(f"Nmap scan failed: {exc}")

    def _tool_http(self):
        def_url = ""
        if self.context.selected_target:
            t = self.target_service.get_target(self.context.selected_target)
            if t:
                def_url = f"http://{t.host}"
        url = self._ask("URL", def_url or "http://127.0.0.1:8080")
        method = self._ask("Method [GET/POST]", "GET").upper()
        body = self._ask("Request Body (optional)") if method == "POST" else None
        try:
            resp = self.http_service.request(url, method=method, body=body)
            self.output(f"HTTP {resp.status_code} ({resp.duration_s:.3f}s)")
            if resp.headers:
                self.output("Headers:\n" + "\n".join(f"  {k}: {v}" for k, v in list(resp.headers.items())[:8]))
            body_preview = resp.body[:500] + ("..." if len(resp.body) > 500 else "")
            self.output(f"Body:\n{body_preview}")
        except Exception as exc:
            self.output(f"HTTP request failed: {exc}")

    def _tool_ffuf(self):
        def_url = ""
        if self.context.selected_target:
            t = self.target_service.get_target(self.context.selected_target)
            if t:
                def_url = f"http://{t.host}/FUZZ"
        url = self._ask("URL with FUZZ", def_url or "http://127.0.0.1/FUZZ")
        wordlist = self._ask("Wordlist path", "/usr/share/wordlists/dirb/common.txt")
        if not os.path.exists(wordlist):
            self.output(f"Wordlist not found: {wordlist}")
            return
        try:
            res = self.ffuf_service.discover_endpoints(url, wordlist)
            self.output(f"Ffuf completed in {res.duration_s:.2f}s with {len(res.matches)} matches:")
            for m in res.matches[:20]:
                self.output(f"  [{m.status}] len={m.length} words={m.words} url={m.url}")
        except Exception as exc:
            self.output(f"Ffuf failed: {exc}")

    def _tool_ssh(self):
        def_host = ""
        if self.context.selected_target:
            t = self.target_service.get_target(self.context.selected_target)
            if t:
                def_host = t.host
        host = self._ask("Host", def_host or self.context.own_ip or "127.0.0.1")
        port = int(self._ask("SSH Port", "22"))
        user = self._ask("User", "root")
        key = self._ask("Identity Key File", "~/.ssh/id_rsa")
        command = self._ask("Remote Command", "uptime")
        try:
            res = self.ssh_service.run(host, command, port=port, username=user, identity_file=key)
            self.output(f"Exit: {res.returncode} ({res.duration_s:.2f}s)\nOutput:\n{res.stdout}")
            if res.stderr:
                self.output(f"Stderr:\n{res.stderr}")
        except Exception as exc:
            self.output(f"SSH execution failed: {exc}")

    def _tool_tcpdump(self):
        iface = self._ask("Interface", self.context.vpn_interface or "any")
        duration = float(self._ask("Duration (s)", "5"))
        bpf = self._ask("BPF filter (e.g. tcp port 80)", "")
        try:
            res = self.tcpdump_service.capture_live(interface=iface, duration_s=duration, bpf_filter=bpf)
            self.output(f"Captured on {res.interface} ({res.duration_s:.2f}s):\n{res.raw_output[:800]}")
        except Exception as exc:
            self.output(f"tcpdump failed: {exc}")

    def _tool_gdb(self):
        binary = self._ask("Target Binary Path")
        if not os.path.exists(binary):
            self.output(f"Binary not found: {binary}")
            return
        self.output("GDB\n  1. Inspect Binary Structure\n  2. Analyze Crash\n  0. Back")
        mode = self._ask("Select", "1")
        if mode == "0":
            return
        try:
            if mode == "1":
                res = self.gdb_service.inspect_binary(binary)
            else:
                core = self._ask("Core Dump Path (optional)") or None
                res = self.gdb_service.analyze_crash(binary, core_path=core)
            self.output(f"GDB Output:\n{res.stdout[:1000]}")
            if res.stderr:
                self.output(f"GDB Stderr:\n{res.stderr[:500]}")
        except Exception as exc:
            self.output(f"GDB inspection failed: {exc}")

    def _tool_system(self):
        self.output(
            "SYSTEM DIAGNOSTICS\n"
            "  1. ss -tulpn (Listening Ports)\n"
            "  2. ss -tan (All TCP Sockets)\n"
            "  3. ps aux (Process List)\n"
            "  4. systemctl status\n"
            "  5. ip addr\n"
            "  6. ip route\n"
            "  7. dig (DNS Lookup)\n"
            "  8. wg show (WireGuard Status)\n"
            "  0. Back"
        )
        choice = self._ask("Select", "0")
        if choice == "0":
            return
        try:
            if choice == "1":
                res = self.system_service.ss_listening()
            elif choice == "2":
                res = self.system_service.ss_all()
            elif choice == "3":
                res = self.system_service.ps_aux()
            elif choice == "4":
                svc = self._ask("Service Name (e.g. nginx)")
                res = self.system_service.systemctl_status(svc)
            elif choice == "5":
                res = self.system_service.ip_addr()
            elif choice == "6":
                res = self.system_service.ip_route()
            elif choice == "7":
                domain = self._ask("Domain", "jjz.jatimprov.go.id")
                res = self.system_service.dig_lookup(domain)
            elif choice == "8":
                res = self.system_service.wireguard_status(self.context.vpn_interface)
            else:
                return
            self.output(f"[{res.tool} {res.subcommand}] exit={res.returncode}:\n{res.stdout}")
            if res.stderr:
                self.output(f"Stderr:\n{res.stderr}")
        except Exception as exc:
            self.output(f"System command failed: {exc}")

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
                "  2. Advance / Set Active Round\n"
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
