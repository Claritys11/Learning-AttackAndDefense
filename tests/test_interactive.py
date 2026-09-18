import tempfile
import time
from attnndef.context import ContextStore, OperatorContext
from attnndef.core.models import Evidence
from attnndef.integrations import NmapAdapter, ReconService, ToolResult
from attnndef.io.sink import LocalSink
from attnndef.operations import ActionCategory, OperationService
from attnndef.targets import Role, Scope, Service, Target, TargetService
from attnndef.ui import InteractiveConsole

class FakeRunner:
    def __init__(self, xml): self.xml = xml
    def run(self, command, *, timeout_s, cwd=None):
        return ToolResult(tuple(command), 0, self.xml, "", 1.0, 1.2)

XML = '<nmaprun><host><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="fixture"/></port></ports></host></nmaprun>'

def make_console(tmp, answers, xml=XML, scope=None):
    store = ContextStore(f"{tmp}/state.db")
    store.save(OperatorContext(operator_name="Kai", selected_target="web"))
    targets = TargetService(f"{tmp}/state.db")
    targets.add_target(Target("web", "web", "127.0.0.1", Role.ENEMY))
    output = []
    console = InteractiveConsole(store, lambda _prompt: next(answers), output.append, ReconService(targets, NmapAdapter(FakeRunner(xml))), scope or Scope(frozenset({Role.ENEMY}), ("127.0.0.0/8",)))
    return console, output

def test_scan_selected_target_displays_observation_and_no_previous():
    with tempfile.TemporaryDirectory() as d:
        answers = iter(["1", "8", "0", "0"])
        console, output = make_console(d, answers)
        console.run()
        text = "\n".join(output)
        assert "Observation #" in text and "80/tcp" in text and "No previous observation." in text

def test_scan_twice_displays_diff():
    with tempfile.TemporaryDirectory() as d:
        store = ContextStore(f"{d}/state.db"); store.save(OperatorContext(selected_target="web"))
        targets = TargetService(f"{d}/state.db"); targets.add_target(Target("web", "web", "127.0.0.1", Role.ENEMY))
        service = ReconService(targets, NmapAdapter(FakeRunner(XML)))
        target = targets.get_target("web"); service.scan_target(target, Scope(frozenset({Role.ENEMY}), ("127.0.0.0/8",)))
        output = []; answers = iter(["1", "8", "0", "0"])
        console = InteractiveConsole(store, lambda _prompt: next(answers), output.append, service, Scope(frozenset({Role.ENEMY}), ("127.0.0.0/8",)))
        console.run()
        assert "No intelligence changes" in "\n".join(output)

def test_compare_explicit_observations():
    with tempfile.TemporaryDirectory() as d:
        store = ContextStore(f"{d}/state.db"); store.save(OperatorContext(selected_target="web"))
        targets = TargetService(f"{d}/state.db"); targets.add_target(Target("web", "web", "127.0.0.1", Role.ENEMY))
        targets.record_observation(__import__('attnndef.targets', fromlist=['Observation']).Observation(None, "web", 1, services=(Service(80, name="http"),)))
        targets.record_observation(__import__('attnndef.targets', fromlist=['Observation']).Observation(None, "web", 2, services=(Service(443, name="https"),)))
        output = []; answers = iter(["1", "9", "1", "2", "0", "0"])
        console = InteractiveConsole(store, lambda _prompt: next(answers), output.append)
        console.run()
        assert "ADDED:" in "\n".join(output)

def test_tools_menu_navigation():
    with tempfile.TemporaryDirectory() as d:
        class MockRunner:
            def run(self, cmd, timeout_s=10.0, cwd=None, input=None):
                if cmd[0] == "curl":
                    return ToolResult(tuple(cmd), 0, "HTTP/1.1 200 OK\r\n\r\nHello", "", 1.0, 1.1)
                elif cmd[0] == "ss":
                    return ToolResult(tuple(cmd), 0, "LISTEN 0 128 0.0.0.0:80", "", 1.0, 1.1)
                return ToolResult(tuple(cmd), 0, "", "", 1.0, 1.1)

        store = ContextStore(f"{d}/state.db")
        store.save(OperatorContext(operator_name="Kai", selected_target="web"))
        targets = TargetService(f"{d}/state.db")
        targets.add_target(Target("web", "web", "127.0.0.1", Role.ENEMY))

        # Test: Main menu (2: Tools) -> HTTP (2) -> GET (1) -> defaults -> confirm "y" -> Back (0) -> Back (0) -> Exit (0)
        answers = iter(["2", "2", "1", "", "", "", "y", "0", "0", "0"])
        output = []
        console = InteractiveConsole(store, lambda _p: next(answers), output.append, runner=MockRunner())
        console.run()
        text = "\n".join(output)
        assert "Tools" in text
        assert "HTTP GET completed" in text
        assert "Status:   200" in text

        # Test: Main menu (2: Tools) -> System Diagnostics (7) -> ss listening (1) -> confirm "y" -> Back (0) -> Back (0) -> Exit (0)
        answers = iter(["2", "7", "1", "y", "0", "0", "0"])
        output = []
        console = InteractiveConsole(store, lambda _p: next(answers), output.append, runner=MockRunner())
        console.run()
        text = "\n".join(output)
        assert "LISTEN 0 128 0.0.0.0:80" in text

def test_ad_and_gzctf_knowledge_console():
    with tempfile.TemporaryDirectory() as d:
        store = ContextStore(f"{d}/state.db")
        store.save(OperatorContext(operator_name="Kai"))

        # Test A&D menu (3) -> select Knowledge Base (10) -> select article 1 -> Back (0) -> Back (0) -> Exit (0)
        answers = iter(["3", "10", "1", "0", "0", "0"])
        output = []
        console = InteractiveConsole(store, lambda _p: next(answers), output.append)
        console.run()
        text = "\n".join(output)
        assert "ATTACK & DEFENSE KNOWLEDGE" in text
        assert "Attack & Defense CTF Overview" in text

        # Test GZCTF menu (4) -> select article 1 -> Back (0) -> Exit (0)
        answers = iter(["4", "1", "0", "0"])
        output = []
        console = InteractiveConsole(store, lambda _p: next(answers), output.append)
        console.run()
        text = "\n".join(output)
        assert "GZCTF PLATFORM GUIDE" in text
        assert "GZCTF Attack & Defense Architecture" in text

def test_competition_menu_and_round_advance():
    with tempfile.TemporaryDirectory() as d:
        store = ContextStore(f"{d}/state.db")
        store.save(OperatorContext(operator_name="Kai", current_round=1, platform="jjz.jatimprov.go.id"))

        # Test Competition menu (5) -> Set round (2) -> enter "3" -> Back (0) -> Exit (0)
        answers = iter(["5", "2", "3", "0", "0"])
        output = []
        console = InteractiveConsole(store, lambda _p: next(answers), output.append)
        console.run()
        text = "\n".join(output)
        assert "jjz.jatimprov.go.id" in text
        assert "Active round set to 3." in text
        assert console.context.current_round == 3

def test_parameter_review_cancel_does_not_execute():
    with tempfile.TemporaryDirectory() as d:
        class TrackingRunner:
            def __init__(self):
                self.calls = []
            def run(self, cmd, timeout_s=10.0, cwd=None, input=None):
                self.calls.append(cmd)
                return ToolResult(tuple(cmd), 0, "", "", 1.0, 1.1)

        runner = TrackingRunner()
        store = ContextStore(f"{d}/state.db")
        store.save(OperatorContext(operator_name="Kai", selected_target="web"))
        targets = TargetService(f"{d}/state.db")
        targets.add_target(Target("web", "web", "127.0.0.1", Role.ENEMY))

        # Main menu (2: Tools) -> Nmap (1) -> Port Scan (2) -> host ("") -> ports ("80") -> Execute? "N" -> Back (0) -> Back (0) -> Exit (0)
        answers = iter(["2", "1", "2", "", "80", "N", "0", "0", "0"])
        output = []
        console = InteractiveConsole(store, lambda _p: next(answers), output.append, runner=runner)
        console.run()
        text = "\n".join(output)
        assert "Operation cancelled." in text
        assert len(runner.calls) == 0

def test_scope_check_rejection_in_interactive_console():
    with tempfile.TemporaryDirectory() as d:
        class TrackingRunner:
            def __init__(self): self.calls = []
            def run(self, cmd, timeout_s=10.0, cwd=None, input=None):
                self.calls.append(cmd)
                return ToolResult(tuple(cmd), 0, "", "", 1.0, 1.1)

        runner = TrackingRunner()
        store = ContextStore(f"{d}/state.db")
        store.save(OperatorContext(operator_name="Kai", selected_target="bad_box"))
        targets = TargetService(f"{d}/state.db")
        targets.add_target(Target("bad_box", "bad_box", "192.168.1.100", Role.ENEMY))
        scope = Scope(frozenset({Role.ENEMY}), ("10.0.0.0/8",), excluded_targets=frozenset({"bad_box"}))

        # Main menu (2: Tools) -> Nmap (1) -> Port Scan (2) -> host ("") -> Back (0) -> Back (0) -> Exit (0)
        answers = iter(["2", "1", "2", "", "0", "0", "0"])
        output = []
        console = InteractiveConsole(store, lambda _p: next(answers), output.append, runner=runner, scope=scope)
        console.run()
        text = "\n".join(output)
        assert "Scope check rejected" in text
        assert len(runner.calls) == 0

def test_operator_workflow_with_evidence_saving():
    import sys
    from attnndef.io.sink import LocalSink
    with tempfile.TemporaryDirectory() as d:
        sink = LocalSink(f"{d}/evidence.jsonl")
        xml_ports = """<nmaprun><host><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/></port></ports></host></nmaprun>"""
        class MockRunner:
            def run(self, cmd, timeout_s=10.0, cwd=None, input=None):
                return ToolResult(tuple(cmd), 0, xml_ports, "", 1.0, 1.25, error_kind="success")

        store = ContextStore(f"{d}/state.db")
        store.save(OperatorContext(operator_name="Kai", selected_target="web"))
        targets = TargetService(f"{d}/state.db")
        targets.add_target(Target("web", "web", "127.0.0.1", Role.ENEMY))

        # Main menu (2: Tools) -> Nmap (1) -> Port Scan (2) -> host ("") -> ports ("80") -> Execute? "y" -> Save evidence? "y" -> Record Operator Action? "y" -> Category ("") -> Summary ("") -> Attach to workflow? "N" -> Back (0) -> Back (0) -> Exit (0)
        answers = iter(["2", "1", "2", "", "80", "y", "y", "y", "", "", "N", "0", "0", "0"])
        output = []
        console = InteractiveConsole(store, lambda _p: next(answers), output.append, runner=MockRunner(), sink=sink)
        console.run()
        text = "\n".join(output)
        assert "✓ Nmap completed" in text
        assert "80/tcp" in text
        assert "✓ Evidence recorded" in text
        assert "✓ Operator Action recorded" in text

        entries = sink.read_all()
        assert len(entries) == 1
        assert entries[0]["kind"] == "tool_nmap"
        assert entries[0]["ok"] is True
        assert entries[0]["payload"]["operation"] == "port_scan"

        actions = console.operation_service.list_actions()
        assert len(actions) == 1
        assert actions[0].tool == "nmap"

def test_ssh_and_gdb_operator_workflows():
    import sys
    with tempfile.TemporaryDirectory() as d:
        class MultiRunner:
            def run(self, cmd, timeout_s=10.0, cwd=None, input=None):
                if cmd[0] == "ssh":
                    return ToolResult(tuple(cmd), 0, "active (running)", "", 1.0, 1.2, error_kind="success")
                elif cmd[0] == "gdb":
                    return ToolResult(tuple(cmd), 0, "Reading symbols from binary...", "", 1.0, 1.3, error_kind="success")
                return ToolResult(tuple(cmd), 0, "", "", 1.0, 1.1)

        store = ContextStore(f"{d}/state.db")
        store.save(OperatorContext(operator_name="Kai", selected_target="box"))
        targets = TargetService(f"{d}/state.db")
        targets.add_target(Target("box", "box", "127.0.0.1", Role.OWN))

        # Test SSH: (2: Tools) -> SSH (4) -> Diagnostic (1) -> Service Status (1) -> svc ("nginx") -> host ("") -> port ("") -> user ("") -> key ("") -> timeout ("") -> Execute? "y" -> Back (0) -> Back (0) -> Exit (0)
        answers = iter(["2", "4", "1", "1", "nginx", "", "", "", "", "", "y", "0", "0", "0"])
        output = []
        console = InteractiveConsole(store, lambda _p: next(answers), output.append, runner=MultiRunner())
        console.run()
        text = "\n".join(output)
        assert "✓ SSH completed" in text
        assert "active (running)" in text

        # Test GDB: (2: Tools) -> GDB (6) -> Binary Inspection (1) -> sys.executable -> Execute? "y" -> Back (0) -> Back (0) -> Exit (0)
        answers = iter(["2", "6", "1", sys.executable, "y", "0", "0", "0"])
        output = []
        console = InteractiveConsole(store, lambda _p: next(answers), output.append, runner=MultiRunner())
        console.run()
        text = "\n".join(output)
        assert "✓ GDB completed" in text
        assert "Reading symbols" in text

def test_interactive_ad_operations_console():
    with tempfile.TemporaryDirectory() as d:
        store = ContextStore(f"{d}/state.db")
        store.save(OperatorContext(operator_name="Kai", selected_target="enemy-box", current_round=1))
        targets = TargetService(f"{d}/state.db")
        targets.add_target(Target("enemy-box", "enemy-box", "10.0.0.5", Role.ENEMY))
        targets.add_target(Target("own-box", "own-box", "10.0.0.2", Role.OWN))

        # Test A&D Menu flows:
        # 1. Round (1) -> Advance (1) -> "2" -> Back (0)
        # 2. Action (2) -> Record (1) -> recon -> "" (def target) -> manual -> scan -> "Initial port sweep" -> completed -> Back (0)
        # 3. Attack (3) -> Record (1) -> "" (def target) -> http/80 -> "SQL injection" -> planned -> "testing" -> Back (0)
        # 4. Defense (4) -> Record (1) -> own-box -> nginx/80 -> "Config hardening" -> completed -> "reloaded" -> Back (0)
        # 5. Flag (5) -> Record (1) -> "" (def target) -> HTTP response -> "flag{test_flag_12345}" -> validated -> "got flag" -> Back (0)
        # 6. SLA (6) -> Record (1) -> own-box -> http/80 -> ok -> "50" -> local -> Back (0)
        # 7. Timeline (7) -> Enter
        # 0. Exit
        answers = iter([
            "3", "1", "1", "2", "0",
            "2", "1", "recon", "", "manual", "scan", "Initial port sweep", "completed", "N", "0",
            "3", "1", "", "http/80", "SQL injection", "planned", "testing", "0",
            "4", "1", "own-box", "nginx/80", "Config hardening", "completed", "reloaded", "0",
            "5", "1", "", "HTTP response", "flag{test_flag_12345}", "validated", "got flag", "0",
            "6", "1", "own-box", "http/80", "ok", "50", "local", "0",
            "7", "",
            "0", "0"
        ])
        output = []
        console = InteractiveConsole(store, lambda _p: next(answers), output.append)
        console.run()
        text = "\n".join(output)

        assert "Local active round set to #2" in text
        assert "Action recorded: [RECON] Initial port sweep" in text
        assert "Attack record created" in text
        assert "Defense record created" in text
        assert "Flag recorded: flag{...12345}" in text
        assert "SLA observation recorded" in text
        assert "ACTIVITY TIMELINE" in text


def test_interactive_workflow_console():
    with tempfile.TemporaryDirectory() as d:
        store = ContextStore(f"{d}/state.db")
        store.save(OperatorContext(operator_name="Kai", selected_target="target-03", current_round=1))
        targets = TargetService(f"{d}/state.db")
        targets.add_target(Target("target-03", "target-03", "10.0.0.13", Role.ENEMY))

        # Test A&D menu (3) -> Workflows (8)
        # 1. Start Workflow (2) -> "Investigate web" -> "Understand HTTP" -> "" (def target) -> "operator note"
        # 2. List Workflows (1) -> Enter
        # 3. Open Workflow (3) -> "" (no id, cancel)
        # 4. Back (0) -> Back (0) -> Exit (0)
        answers = iter([
            "3", "8",
            "2", "Investigate web", "Understand HTTP", "", "operator note",
            "1", "",
            "3", "",
            "0", "0", "0"
        ])
        output = []
        console = InteractiveConsole(store, lambda _p: next(answers), output.append)
        console.run()
        text = "\n".join(output)

        assert "OPERATOR WORKFLOWS" in text
        assert "Workflow started:" in text
        assert "Investigate web" in text
        assert "WORKFLOW LIST" in text


def test_interactive_mission_cockpit_flow():
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        store = ContextStore(db_path)
        store.save(OperatorContext(operator_name="Kai", selected_target="enemy-03", current_round=1, session_id="sess-cockpit"))
        targets = TargetService(db_path)
        targets.add_target(Target("enemy-03", "enemy-03", "10.0.0.13", Role.ENEMY))

        svc = OperationService(db_path, target_service=targets)
        svc.create_session(session_id="sess-cockpit", operator="Kai")
        svc.start_round("sess-cockpit", 1)
        wf = svc.create_workflow("sess-cockpit", 1, "Investigate web", target_id="enemy-03")

        # Flow:
        # A&D (3) -> Missions (9)
        # List (1)
        # Create (2) -> wf.workflow_id[:8] -> "" (def target: enemy-03) -> "8080" -> "tcp" -> "HTTP Inspection" -> "Probe endpoints" -> "" (notes) -> "y" (open cockpit)
        # In Cockpit:
        # 1: Record Action -> "recon" -> "nmap" -> "port_scan" -> "Scan 8080" -> "completed"
        # 2: Record Attack -> "traversal" -> "success" -> "poc worked"
        # 3: Record Defense -> "filter" -> "completed" -> "patched"
        # 4: Record Flag -> "flag{cockpit_flag_test}" -> "validated" -> "captured"
        # 5: Record Verification -> "" -> "manual" -> "Verify patch" -> "verified" -> "n" (SLA) -> "n" (scan)
        # 9: Complete Mission -> "Mission completed successfully"
        # 0: Back
        # 0: Back (from missions menu)
        # 0: Back (from A&D menu)
        # 0: Exit (from main menu)
        answers = iter([
            "3", "9",
            "1",
            "2", wf.workflow_id[:8], "", "8080", "tcp", "HTTP Inspection", "Probe endpoints", "", "y",
            "1", "recon", "nmap", "port_scan", "Scan 8080", "completed",
            "2", "traversal", "success", "poc worked",
            "3", "filter", "completed", "patched",
            "4", "flag{cockpit_flag_test}", "validated", "captured",
            "5", "", "manual", "Verify patch", "verified", "n", "n",
            "9", "Mission completed successfully",
            "0",
            "0", "0", "0"
        ])
        output = []
        console = InteractiveConsole(store, lambda _p: next(answers), output.append)
        console.run()
        text = "\n".join(output)

        assert "MISSIONS" in text
        assert "✓ Mission created:" in text
        assert "HTTP Inspection" in text
        assert "Target:   enemy-03" in text
        assert "Service:  TCP/8080" in text
        assert "✓ Action recorded: [RECON] Scan 8080" in text
        assert "✓ Attack recorded: [SUCCESS] traversal on enemy-03 (tcp/8080)" in text
        assert "✓ Defense recorded: [COMPLETED] filter on enemy-03" in text
        assert "✓ Flag recorded:" in text
        assert "✓ Verification action recorded:" in text
        assert "✓ Mission completed." in text


def test_interactive_mission_awareness_and_evidence_inspection():
    with tempfile.TemporaryDirectory() as d:
        db_path = f"{d}/state.db"
        sink_path = f"{d}/sink.jsonl"
        store = ContextStore(db_path)
        store.save(OperatorContext(operator_name="Kai", selected_target="enemy-03", current_round=1, session_id="sess-aware"))
        targets = TargetService(db_path)
        targets.add_target(Target("enemy-03", "enemy-03", "10.0.0.13", Role.ENEMY))

        sink = LocalSink(sink_path)
        ev = Evidence(
            id="ev-cockpit-01",
            ts=time.time(),
            kind="tool_nmap",
            target_id="enemy-03",
            ok=True,
            payload={"summary": "Nmap scan result", "ports": [8080]},
        )
        sink.write(ev)

        svc = OperationService(db_path, target_service=targets)
        svc.create_session(session_id="sess-aware", operator="Kai")
        svc.start_round("sess-aware", 1)
        wf = svc.create_workflow("sess-aware", 1, "Awareness Workflow", target_id="enemy-03")
        m = svc.create_mission(wf.workflow_id, "enemy-03", 8080, title="Awareness Cockpit Mission")
        svc.start_mission(m.mission_id)

        # Record action linked to evidence
        svc.record_action(
            "sess-aware", 1, ActionCategory.RECON, "nmap", "scan", "Port 8080 scan",
            target_id="enemy-03", workflow_id=wf.workflow_id, mission_id=m.mission_id,
            evidence_id=ev.id,
        )

        # Flow:
        # A&D (3) -> Missions (9) -> Open (3) -> m.mission_id[:8]
        # In Cockpit:
        # 11: Situational Awareness View
        # 12: Inspect Correlated Evidence -> 1 (select first item) -> display payload
        # 0: Back
        # 0: Back (from missions menu)
        # 0: Back (from A&D menu)
        # 0: Exit (from main menu)
        answers = iter([
            "3", "9", "3", m.mission_id[:8],
            "11",
            "12", "1",
            "0",
            "0", "0", "0"
        ])
        output = []
        console = InteractiveConsole(store, lambda _p: next(answers), output.append, sink=sink)
        console.run()
        text = "\n".join(output)

        assert f"SITUATIONAL AWARENESS: MISSION #{m.mission_id[:8]}" in text
        assert "Awareness Cockpit Mission" in text
        assert "CORRELATED EVIDENCE ARTIFACTS:" in text
        assert "ev-cockpit-01" in text
        assert "EVIDENCE: ev-cockpit-01" in text
        assert "Nmap scan result" in text
