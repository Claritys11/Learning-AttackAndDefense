import time

from attnndef.attack.extractor import RegexExtractor
from attnndef.attack.runner import AttackRunner
from attnndef.core.models import Role, Target


def make_targets(n):
    return [
        Target(id=f"t{i}", name=f"t{i}", host="127.0.0.1", port=9000 + i, role=Role.ENEMY)
        for i in range(n)
    ]


def test_run_collects_flags_for_all_targets():
    def attack_fn(target):
        return f"FLAG{{{target.id}}}"

    runner = AttackRunner(attack_fn=attack_fn, extractor=RegexExtractor(), max_workers=3)
    results = runner.run(make_targets(5))
    assert {r.target_id for r in results} == {f"t{i}" for i in range(5)}
    assert all(r.success for r in results)


def test_run_marks_timeout():
    def slow_attack(target):
        time.sleep(0.5)
        return "FLAG{never}"

    runner = AttackRunner(
        attack_fn=slow_attack, extractor=RegexExtractor(), max_workers=2, per_target_timeout_s=0.05
    )
    results = runner.run(make_targets(2))
    assert all(r.error == "timeout" and not r.success for r in results)


def test_run_captures_exceptions_as_failures():
    def broken_attack(target):
        raise RuntimeError("boom")

    runner = AttackRunner(attack_fn=broken_attack, extractor=RegexExtractor())
    [result] = runner.run(make_targets(1))
    assert result.success is False
    assert "boom" in result.error


def test_bounded_concurrency_never_exceeds_max_workers():
    in_flight = {"current": 0, "max_seen": 0}

    def attack_fn(target):
        in_flight["current"] += 1
        in_flight["max_seen"] = max(in_flight["max_seen"], in_flight["current"])
        time.sleep(0.05)
        in_flight["current"] -= 1
        return "FLAG{ok}"

    runner = AttackRunner(attack_fn=attack_fn, extractor=RegexExtractor(), max_workers=2)
    runner.run(make_targets(6))
    assert in_flight["max_seen"] <= 2
