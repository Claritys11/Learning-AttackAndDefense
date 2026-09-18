from attnndef.targets import Observation, Service, compare_observations, diff_history

def obs(i, services, status="up"):
    return Observation(i, "t", float(i or 0), services=tuple(services), status=status)

def test_diff_added_removed_changed_and_status():
    old = obs(1, [Service(22, name="ssh", version="9.2"), Service(80, name="http")])
    new = obs(2, [Service(22, name="ssh", version="9.6"), Service(443, name="https")])
    diff = compare_observations(old, new)
    assert [x.kind.value for x in diff.entries] == ["added", "removed", "changed"]
    assert "443/tcp https" in diff.render()

def test_diff_status_only_and_unchanged_empty():
    old = obs(1, [Service(80, name="http", status="open")], "up")
    new = obs(2, [Service(80, name="http", status="closed")], "down")
    assert compare_observations(old, new).status_changed
    same = compare_observations(old, obs(3, [Service(80, name="http", status="open")], "up"))
    assert not same.entries
    assert diff_history([new]) is None

def test_empty_observations_are_unchanged():
    assert not compare_observations(obs(1, []), obs(2, [])).entries
