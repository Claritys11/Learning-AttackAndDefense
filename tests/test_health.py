import time

from attnndef.defense.health import HealthChecker


def test_health_ok(own_target):
    checker = HealthChecker(check_fn=lambda t: True)
    result = checker.check(own_target)
    assert result.ok is True


def test_health_false_on_check_failure(own_target):
    checker = HealthChecker(check_fn=lambda t: False)
    result = checker.check(own_target)
    assert result.ok is False


def test_health_times_out(own_target):
    def slow(t):
        time.sleep(0.3)
        return True

    checker = HealthChecker(check_fn=slow, timeout_s=0.05)
    result = checker.check(own_target)
    assert result.ok is False
    assert "TimeoutError" in result.details or result.details
