from attnndef.targets import Observation, Service, compare_observations, diff_history

def obs(i, services, status="up", session="s", round_id=1):
    return Observation(i, "t", float(i or 0), session_id=session, round_id=round_id, services=tuple(services), status=status)

def test_diff_added_removed_changed_and_status():
    old = obs(1, [Service(22, name="ssh", version="9.2"), Service(80, name="http")])
    new = obs(2, [Service(22, name="ssh", version="9.6"), Service(443, name="https")])
    diff = compare_observations(old, new)
    assert [x.kind.value for x in diff.entries] == ["added", "removed", "changed"]
    assert diff.changed[0].changes == {"version": ("9.2", "9.6")}
    assert "443/tcp https" in diff.render()

def test_combined_status_and_metadata_is_one_entry():
    old = obs(1, [Service(22, name="ssh", version="9.2", status="open")])
    new = obs(2, [Service(22, name="unknown", version="9.6", status="closed")])
    diff = compare_observations(old, new)
    assert len(diff.entries) == 1
    assert diff.entries[0].kind.value == "status_changed"
    assert diff.entries[0].field_changes == (("name", ("ssh", "unknown")), ("version", ("9.2", "9.6")), ("status", ("open", "closed")))

def test_metadata_order_and_result_metadata_are_structured():
    diff = compare_observations(obs(4, [Service(80, name="new", version="2")], round_id=4), obs(5, [Service(80, name="old", version="1")], round_id=5))
    assert diff.previous_id == 4 and diff.current_id == 5
    assert diff.previous_round_id == 4 and diff.current_round_id == 5
    assert tuple(diff.entries[0].changes) == ("name", "version")
    assert "→" in diff.render()

def test_diff_history_order_is_explicit_and_empty_is_unchanged():
    old, new = obs(1, [Service(80)]), obs(2, [Service(443)])
    assert diff_history([new, old]).previous_id == 1
    assert diff_history([old, new], newest_first=False).current_id == 2
    assert not compare_observations(obs(1, []), obs(2, [])).entries
    assert diff_history([new]) is None
