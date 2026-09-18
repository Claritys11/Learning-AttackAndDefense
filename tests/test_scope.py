import pytest
from attnndef.targets import Role, Scope, ScopeMode, Target

def test_scope_allows_role_and_network():
    scope = Scope(frozenset({Role.ENEMY}), ("10.10.20.0/24",), frozenset({"excluded"}), ScopeMode.COMPETITION)
    assert scope.validate(Target("ok", "ok", "10.10.20.11", Role.ENEMY))[0]
    assert not scope.validate(Target("own", "own", "10.10.20.12", Role.OWN))[0]
    assert not scope.validate(Target("excluded", "excluded", "10.10.20.13", Role.ENEMY))[0]
    assert not scope.validate(Target("outside", "outside", "10.10.30.11", Role.ENEMY))[0]

def test_scope_require_raises():
    with pytest.raises(ValueError, match="out of scope"):
        Scope(frozenset({Role.ENEMY}), ("127.0.0.1/32",)).require(Target("x", "x", "127.0.0.2", Role.ENEMY))
