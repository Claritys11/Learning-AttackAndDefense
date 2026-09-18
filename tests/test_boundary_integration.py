from attnndef.integrations import NmapAdapter
from attnndef.targets import ExecutionBoundary, Role, Scope, Target

class RecordingRunner:
    def __init__(self): self.called = False
    def run(self, *args, **kwargs): self.called = True; raise AssertionError("runner must not be called")

def test_out_of_scope_never_reaches_tool_runner():
    runner = RecordingRunner()
    adapter = NmapAdapter(runner)
    target = Target("outside", "outside", "10.0.0.1", Role.ENEMY)
    import pytest
    with pytest.raises(ValueError, match="out of scope"):
        adapter.scan_target(target, Scope(frozenset({Role.ENEMY}), ("127.0.0.0/8",)))
    assert not runner.called
