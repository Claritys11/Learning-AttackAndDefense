import tempfile
from attnndef.integrations import DiscoveryAdapter, DiscoveryService, ToolResult, parse_discovery_xml
from attnndef.targets import Role, Scope, TargetService

XML = '<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/></host></nmaprun>'
class FakeRunner:
    def run(self, command, *, timeout_s, cwd=None):
        assert command[1] == "-sn"
        return ToolResult(tuple(command), 0, XML, "", 1, 2)

def test_discovery_parser_and_registry():
    assert parse_discovery_xml(XML)[0].host == "127.0.0.1"
    with tempfile.TemporaryDirectory() as d:
        registry = TargetService(f"{d}/targets.db")
        scope = Scope(frozenset(), ("127.0.0.0/8",))
        hosts = DiscoveryService(registry, DiscoveryAdapter(FakeRunner())).discover("127.0.0.0/30", scope)
        assert hosts[0].status == "up"
        assert registry.get_target("discovered-127.0.0.1").role is Role.UNKNOWN

def test_discovery_rejects_network_outside_scope():
    with tempfile.TemporaryDirectory() as d:
        registry = TargetService(f"{d}/targets.db")
        scope = Scope(frozenset(), ("127.0.0.0/8",))
        import pytest
        with pytest.raises(ValueError, match="outside configured scope"):
            DiscoveryService(registry, DiscoveryAdapter(FakeRunner())).discover("10.0.0.0/24", scope)
