from attnndef.defense.patcher import TextReplacePatch


def test_dry_run_does_not_touch_file(own_target, tmp_config):
    original = tmp_config.read_text()
    patcher = TextReplacePatch(tmp_config.parent / "backups", "DEBUG=true", "DEBUG=false")
    plan = patcher.dry_run(own_target)
    assert plan.dry_run is True
    assert plan.applied is False
    assert tmp_config.read_text() == original
    assert "DEBUG=false" in plan.diff_preview


def test_apply_backs_up_and_mutates(own_target, tmp_config):
    patcher = TextReplacePatch(tmp_config.parent / "backups", "DEBUG=true", "DEBUG=false")
    plan = patcher.apply(own_target)
    assert plan.applied is True
    assert "DEBUG=false" in tmp_config.read_text()
    assert "DEBUG=true" not in tmp_config.read_text()
    from pathlib import Path

    assert Path(plan.backup_path).exists()
    assert "DEBUG=true" in Path(plan.backup_path).read_text()


def test_rollback_restores_original(own_target, tmp_config):
    original = tmp_config.read_text()
    patcher = TextReplacePatch(tmp_config.parent / "backups", "DEBUG=true", "DEBUG=false")
    plan = patcher.apply(own_target)
    assert tmp_config.read_text() != original

    patcher.rollback(plan, own_target)
    assert tmp_config.read_text() == original
    assert plan.rolled_back is True
