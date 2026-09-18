from __future__ import annotations

from ..context import ContextStore, OperatorContext

class InteractiveConsole:
    def __init__(self, store: ContextStore, input_fn=input, output_fn=print):
        self.store, self.input, self.output = store, input_fn, output_fn
        self.context = store.load()

    def _ask(self, label, default=""):
        value = self.input(f"{label}{f' [{default}]' if default else ''}: ").strip()
        return value or default

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
        if self.context is None:
            self.wizard()
        while True:
            self.output("MAIN MENU\n  1. Targets\n  2. Attack\n  3. Defense\n  4. Monitor\n  5. Flags\n  6. Competition\n  7. Learning\n  8. Evidence\n  9. Settings\n  0. Exit")
            choice = self._ask("Select", "0")
            if choice == "0" or choice.lower() in {"q", "quit", "exit"}:
                self.output("Bye.")
                return 0
            if choice == "9":
                self.output(f"Profile: {self.context.profile} | Team: {self.context.team_name or '(unset)'} | Round: {self.context.current_round}")
            else:
                self.output("This Phase 1 menu is ready; the selected workflow is implemented in the direct CLI and will be connected in the next phase.")
        
