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

        # Test: Main menu (2: Tools) -> HTTP (2) -> default inputs -> Back (0) -> Exit (0)
        answers = iter(["2", "2", "", "", "0", "0"])
        output = []
        console = InteractiveConsole(store, lambda _p: next(answers), output.append, runner=MockRunner())
        console.run()
        text = "\n".join(output)
        assert "OPERATOR TOOLS" in text
        assert "HTTP 200" in text

        # Test: Main menu (2: Tools) -> System Diagnostics (7) -> ss listening (1) -> Back (0) -> Exit (0)
        answers = iter(["2", "7", "1", "0", "0"])
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
