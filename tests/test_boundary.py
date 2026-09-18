import tempfile
import pytest
from attnndef.targets import ExecutionBoundary, OperationKind, Role, Scope, Target

def boundary():
    return ExecutionBoundary(Scope(frozenset({Role.ENEMY}), ("127.0.0.0/8",), frozenset({"excluded"})))

def test_boundary_allows_scoped_enemy_attack():
    boundary().authorize_attack(Target("enemy", "enemy", "127.0.0.2", Role.ENEMY))

def test_boundary_rejects_out_of_scope_excluded_and_invalid_attack_targets():
    guard = boundary()
    with pytest.raises(ValueError, match="out of scope"):
        guard.authorize_attack(Target("outside", "outside", "10.0.0.1", Role.ENEMY))
    with pytest.raises(ValueError, match="excluded"):
        guard.authorize_attack(Target("excluded", "excluded", "127.0.0.3", Role.ENEMY))
    with pytest.raises(ValueError, match="role own is outside scope"):
        guard.authorize_attack(Target("own", "own", "127.0.0.4", Role.OWN))

def test_attack_boundary_rejects_non_enemy_after_scope_allows_it():
    guard = ExecutionBoundary(Scope(frozenset({Role.OWN, Role.ENEMY}), ("127.0.0.0/8",)))
    with pytest.raises(ValueError, match="ENEMY"):
        guard.authorize_attack(Target("own", "own", "127.0.0.4", Role.OWN))

def test_intelligence_boundary_can_read_allowed_non_enemy_without_attack_authorization():
    guard = ExecutionBoundary(Scope(frozenset(), ("127.0.0.0/8",)))
    guard.authorize(Target("own", "own", "127.0.0.4", Role.OWN), OperationKind.INTELLIGENCE)
