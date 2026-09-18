from attnndef.targets import Role, Target, TargetService

def test_target_role_filter_and_upsert():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        svc = TargetService(f"{d}/targets.db")
        svc.add_target(Target("a", "a", "127.0.0.1", Role.ENEMY))
        svc.add_target(Target("b", "b", "127.0.0.2", Role.OWN))
        assert [x.id for x in svc.list_targets(Role.ENEMY)] == ["a"]
        svc.upsert_target(Target("a", "a2", "127.0.0.1", Role.ENEMY, ("web",)))
        assert svc.get_target("a").name == "a2"
        assert svc.get_target("a").tags == ("web",)
