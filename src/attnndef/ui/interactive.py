from __future__ import annotations

from ..context import ContextStore, OperatorContext
from ..integrations import ReconService
from ..targets import Role, Scope, Target, TargetService, diff_history, compare_observations

class InteractiveConsole:
    def __init__(self, store: ContextStore, input_fn=input, output_fn=print, recon_service: ReconService | None = None, scope: Scope | None = None):
        self.store, self.input, self.output = store, input_fn, output_fn
        self.context = store.load()
        self.target_service = TargetService(store.path)
        self.recon_service = recon_service
        self.scope = scope

    def _ask(self, label, default=""):
        value = self.input(f"{label}{f' [{default}]' if default else ''}: ").strip()
        return value or default

    def _target_or_selected(self):
        tid = self.context.selected_target or self._ask("Target ID")
        target = self.target_service.get_target(tid)
        if target is None: self.output("Target not found.")
        return target

    def _show_observation(self, observation):
        self.output(f"Observation #{observation.id}\nStatus: {observation.status}\nServices:")
        for service in observation.services:
            self.output(f"  {service.port}/{service.protocol}  {service.name}  {service.version}".rstrip())

    def _scan_target(self):
        target = self._target_or_selected()
        if target is None: return
        if self.recon_service is None or self.scope is None:
            self.output("Scan is not configured; no operation was performed.")
            return
        try:
            observation = self.recon_service.scan_target(target, self.scope, session_id=self.context.session_id, round_id=self.context.current_round)
        except ValueError as exc:
            self.output(f"Scan rejected: {exc}"); return
        except Exception as exc:
            self.output(f"Scan failed: {exc}"); return
        self._show_observation(observation)
        history = self.target_service.history(target.id)
        if len(history) > 1:
            intelligence = diff_history(history)
            self.output(f"Changes since observation #{intelligence.previous_id}:\n{intelligence.render()}" if intelligence and intelligence.entries else "No intelligence changes since the previous observation.")
        else:
            self.output("No previous observation.")

    def _compare_observations(self):
        target = self._target_or_selected()
        if target is None: return
        history = self.target_service.history(target.id)
        if not history: self.output("No observations."); return
        self.output("Observations:\n" + "\n".join(f"  #{o.id}  round={o.round_id}  status={o.status}" for o in history))
        older_id = int(self._ask("Older observation ID"))
        newer_id = int(self._ask("Newer observation ID"))
        observations = {o.id: o for o in history}
        if older_id not in observations or newer_id not in observations:
            self.output("Observation not found."); return
        self.output(compare_observations(observations[older_id], observations[newer_id]).render())

    def _targets_menu(self):
        while True:
            self.output("TARGETS\n  1. List Targets\n  2. Select Target\n  3. Add Target\n  4. Edit Target\n  5. Remove Target\n  6. Target Details\n  7. Intelligence History\n  8. Scan Target\n  9. Compare Observations\n  0. Back")
            choice = self._ask("Select", "0")
            if choice == "0": return
            if choice == "1":
                rows = self.target_service.list_targets()
                self.output("\n".join(f"{t.id}  {t.name}  {t.host}  {t.role.value}  [{', '.join(t.tags)}]" for t in rows) or "No targets.")
            elif choice == "2":
                target = self.target_service.get_target(self._ask("Target ID"))
                if target is None: self.output("Target not found.")
                else:
                    self.context.selected_target = target.id; self.store.save(self.context)
                    self.output(f"Selected target: {target.name} ({target.host})")
            elif choice == "3":
                role = self._ask("Role", "unknown").lower()
                try: role_enum = Role(role)
                except ValueError: self.output("Invalid role."); continue
                tags = tuple(x.strip() for x in self._ask("Tags (comma separated)").split(",") if x.strip())
                self.target_service.add_target(Target(self._ask("ID"), self._ask("Name"), self._ask("Host"), role_enum, tags)); self.output("Target added.")
            elif choice == "4":
                tid = self._ask("Target ID"); current = self.target_service.get_target(tid)
                if current is None: self.output("Target not found.")
                else:
                    role = self._ask("Role", current.role.value).lower()
                    try: role_enum = Role(role)
                    except ValueError: self.output("Invalid role."); continue
                    tags = tuple(x.strip() for x in self._ask("Tags", ",".join(current.tags)).split(",") if x.strip())
                    self.target_service.update_target(tid, name=self._ask("Name", current.name), host=self._ask("Host", current.host), role=role_enum, tags=tags, notes=self._ask("Notes", current.notes)); self.output("Target updated.")
            elif choice == "5": self.output("Removed." if self.target_service.remove_target(self._ask("Target ID")) else "Target not found.")
            elif choice in {"6", "7"}:
                target = self._target_or_selected()
                if choice == "6": self.output(str(target) if target else "Target not found.")
                else: self.output("\n".join(str(o) for o in self.target_service.history(target.id)) if target else "Target not found.")
            elif choice == "8": self._scan_target()
            elif choice == "9": self._compare_observations()

    def wizard(self):
        self.output("\nATTNDEF — Attack & Defense Console\nNo operator configuration found.\n")
        choices = {"1": "Learning Lab", "2": "Local Attack & Defense", "3": "Competition"}
        mode = choices.get(self._ask("Profile [1-3]", "1"), "Learning Lab")
        self.context = OperatorContext(profile=mode)
        self.context.operator_name = self._ask("Operator Name"); self.context.team_name = self._ask("Team Name"); self.context.team_id = self._ask("Team ID")
        self.context.vpn_interface = self._ask("VPN Interface (optional)"); self.context.own_ip = self._ask("Own IP (optional)"); self.context.team_subnet = self._ask("Team subnet (optional)"); self.context.enemy_subnet = self._ask("Enemy subnet (optional)"); self.context.platform = self._ask("Platform (optional)"); self.context.competition_name = self._ask("Competition name (optional)"); self.context.flag_format = self._ask("Flag format (optional)")
        self.store.save(self.context); self.output("Configuration saved.\n")

    def run(self):
        if self.context is None: self.wizard()
        while True:
            self.output("MAIN MENU\n  1. Targets\n  2. Attack\n  3. Defense\n  4. Monitor\n  5. Flags\n  6. Competition\n  7. Learning\n  8. Evidence\n  9. Settings\n  0. Exit")
            choice = self._ask("Select", "0")
            if choice == "0" or choice.lower() in {"q", "quit", "exit"}: self.output("Bye."); return 0
            if choice == "1": self._targets_menu()
            elif choice == "9": self.output(f"Profile: {self.context.profile} | Team: {self.context.team_name or '(unset)'} | Target: {self.context.selected_target or '(none)'} | Round: {self.context.current_round}")
            else: self.output("This workflow is not enabled yet; no fake operation was performed.")
