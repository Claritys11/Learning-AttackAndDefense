import tempfile
from attnndef.context import ContextStore, OperatorContext
from attnndef.integrations import NmapAdapter, ReconService, ToolResult
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

        # Test A&D menu (3) -> select article 1 -> Back (0) -> Exit (0)
        answers = iter(["3", "1", "0", "0"])
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

        # Main menu (2: Tools) -> Nmap (1) -> Port Scan (2) -> host ("") -> ports ("80") -> Execute? "y" -> Save evidence? "y" -> Back (0) -> Back (0) -> Exit (0)
        answers = iter(["2", "1", "2", "", "80", "y", "y", "0", "0", "0"])
        output = []
        console = InteractiveConsole(store, lambda _p: next(answers), output.append, runner=MockRunner(), sink=sink)
        console.run()
        text = "\n".join(output)
        assert "✓ Nmap completed" in text
        assert "80/tcp" in text
        assert "✓ Evidence recorded" in text

        entries = sink.read_all()
        assert len(entries) == 1
        assert entries[0]["kind"] == "tool_nmap"
        assert entries[0]["ok"] is True
        assert entries[0]["payload"]["operation"] == "port_scan"

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
