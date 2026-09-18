import tempfile
import pytest
from attnndef.targets import Observation, Role, Service, Target, TargetService

def test_target_crud_and_temporal_history():
    with tempfile.TemporaryDirectory() as d:
        svc = TargetService(f"{d}/targets.db")
        target = svc.add_target(Target("web01", "web01", "127.0.0.1", Role.ENEMY, ("web", "php")))
        assert svc.get_target("web01") == target
        first = svc.record_observation(Observation(None, "web01", 1.0, session_id="s1", round_id=1, services=(Service(8080, name="http", version="php"),), status="up"))
        second = svc.record_observation(Observation(None, "web01", 2.0, session_id="s1", round_id=2, services=(Service(8080, name="http", version="php", status="degraded"),), status="degraded"))
        history = svc.history("web01")
        assert first.id and second.id and history[0].id == second.id
        assert history[0].round_id == 2
        assert history[0].services[0].status == "degraded"
        assert svc.remove_target("web01") is True
        assert svc.get_target("web01") is None

def test_target_role_filter_and_upsert():
    with tempfile.TemporaryDirectory() as d:
        svc = TargetService(f"{d}/targets.db")
        svc.add_target(Target("a", "a", "127.0.0.1", Role.ENEMY))
        svc.add_target(Target("b", "b", "127.0.0.2", Role.OWN))
        assert [x.id for x in svc.list_targets(Role.ENEMY)] == ["a"]
        svc.upsert_target(Target("a", "a2", "127.0.0.1", Role.ENEMY, ("web",)))
        assert svc.get_target("a").name == "a2"
        assert svc.get_target("a").tags == ("web",)

def test_observation_requires_existing_target():
    with tempfile.TemporaryDirectory() as d:
        with pytest.raises(ValueError, match="unknown target"):
            TargetService(f"{d}/targets.db").record_observation(Observation(None, "missing", 1.0))
