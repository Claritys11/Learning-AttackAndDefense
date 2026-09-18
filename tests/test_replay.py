from attnndef.attack.extractor import RegexExtractor
from attnndef.attack.runner import AttackRunner
from attnndef.defense.health import HealthChecker
from attnndef.defense.patcher import TextReplacePatch
from attnndef.defense.replay import ExploitReplay
from tests.fixtures.mock_service import attack_fn, check_fn


def test_replay_before_patch_exploit_still_works(own_target):
    runner = AttackRunner(attack_fn=attack_fn, extractor=RegexExtractor())
    checker = HealthChecker(check_fn=check_fn)
    replay = ExploitReplay(runner, checker)
    verdict = replay.verify(own_target)
    assert verdict.exploit_still_works is True
    assert verdict.patch_confirmed is False


def test_replay_after_patch_confirms_fix(own_target, tmp_config):
    patcher = TextReplacePatch(tmp_config.parent / "backups", "DEBUG=true", "DEBUG=false")
    patcher.apply(own_target)

    runner = AttackRunner(attack_fn=attack_fn, extractor=RegexExtractor())
    checker = HealthChecker(check_fn=check_fn)
    replay = ExploitReplay(runner, checker)
    verdict = replay.verify(own_target)

    assert verdict.exploit_still_works is False
    assert verdict.healthy is True
    assert verdict.patch_confirmed is True
