import tempfile
from attnndef.integrations import NmapAdapter, ReconService, ToolResult
from attnndef.targets import Role, Scope, Target, TargetService

class FakeRunner:
    def run(self, command, *, timeout_s, cwd=None):
        return ToolResult(tuple(command), 0, '<nmaprun><host><ports><port protocol="tcp" portid="8080"><state state="open"/><service name="http" product="fixture"/></port></ports></host></nmaprun>', '', 1.0, 1.1)

def test_recon_records_observation_after_scope():
    with tempfile.TemporaryDirectory() as d:
        store = TargetService(f"{d}/targets.db")
        target = store.add_target(Target("web", "web", "127.0.0.1", Role.ENEMY))
        obs = ReconService(store, NmapAdapter(FakeRunner())).scan_target(target, Scope(frozenset({Role.ENEMY}), ("127.0.0.0/8",)), session_id="s", round_id=3)
        assert obs.id and obs.round_id == 3
        assert obs.services[0].port == 8080
