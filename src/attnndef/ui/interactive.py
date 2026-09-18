from __future__ import annotations

from ..context import ContextStore, OperatorContext
from ..targets import Role, Target, TargetService

class InteractiveConsole:
    def __init__(self, store: ContextStore, input_fn=input, output_fn=print):
        self.store, self.input, self.output = store, input_fn, output_fn
        self.context = store.load()
        self.target_service = TargetService(store.path)

    def _ask(self, label, default=""):
        value = self.input(f"{label}{f' [{default}]' if default else ''}: ").strip()
        return value or default

    def _targets_menu(self):
        while True:
            self.output("TARGETS\n  1. List Targets\n  2. Select Target\n  3. Add Target\n  4. Remove Target\n  5. Target Details\n  6. Intelligence History\n  0. Back")
            choice = self._ask("Select", "0")
            if choice == "0": return
            if choice == "1":
                rows = self.target_service.list_targets()
                self.output("\n".join(f"{t.id}  {t.name}  {t.host}  {t.role.value}  [{', '.join(t.tags)}]" for t in rows) or "No targets.")
            elif choice == "2":
                target = self.target_service.get_target(self._ask("Target ID"))
                if target is None: self.output("Target not found.")
                else:
                    self.context.selected_target = target.id
                    self.store.save(self.context)
                    self.output(f"Selected target: {target.name} ({target.host})")
            elif choice == "3":
                role = self._ask("Role", "unknown").lower()
                try: role_enum = Role(role)
                except ValueError: self.output("Invalid role."); continue
                tags = tuple(x.strip() for x in self._ask("Tags (comma separated)").split(",") if x.strip())
                self.target_service.add_target(Target(self._ask("ID"), self._ask("Name"), self._ask("Host"), role_enum, tags))
                self.output("Target added.")
            elif choice == "4":
                self.output("Removed." if self.target_service.remove_target(self._ask("Target ID")) else "Target not found.")
            elif choice in {"5", "6"}:
                tid = self._ask("Target ID", self.context.selected_target)
                target = self.target_service.get_target(tid)
                if choice == "5": self.output(str(target) if target else "Target not found.")
                else: self.output("\n".join(str(o) for o in self.target_service.history(tid)) or "No observations.")

    def wizard(self):
        self.output("\nATTNDEF — Attack & Defense Console\nNo operator configuration found.\n")
        choices = {"1": "Learning Lab", "2": "Local Attack & Defense", "3": "Competition"}
        mode = choices.get(self._ask("Profile [1-3]", "1"), "Learning Lab")
        self.context = OperatorContext(profile=mode)
        self.context.operator_name = self._ask("Operator Name")
        self.context.team_name = self._ask("Team Name")
        self.context.team_id = self._ask("Team ID")
        self.context.vpn_interface = self._ask("VPN Interface (optional)")
        self.context.own_ip = self._ask("Own IP (optional)")
        self.context.team_subnet = self._ask("Team subnet (optional)")
        self.context.enemy_subnet = self._ask("Enemy subnet (optional)")
        self.context.platform = self._ask("Platform (optional)")
        self.context.competition_name = self._ask("Competition name (optional)")
        self.context.flag_format = self._ask("Flag format (optional)")
        self.store.save(self.context)
        self.output("Configuration saved.\n")

    def run(self):
        if self.context is None: self.wizard()
        while True:
            self.output("MAIN MENU\n  1. Targets\n  2. Attack\n  3. Defense\n  4. Monitor\n  5. Flags\n  6. Competition\n  7. Learning\n  8. Evidence\n  9. Settings\n  0. Exit")
            choice = self._ask("Select", "0")
            if choice == "0" or choice.lower() in {"q", "quit", "exit"}: self.output("Bye."); return 0
            if choice == "1": self._targets_menu()
            elif choice == "9": self.output(f"Profile: {self.context.profile} | Team: {self.context.team_name or '(unset)'} | Target: {self.context.selected_target or '(none)'} | Round: {self.context.current_round}")
            else: self.output("This workflow is not enabled yet; no fake operation was performed.")
