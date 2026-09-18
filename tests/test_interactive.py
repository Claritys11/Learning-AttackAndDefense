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
