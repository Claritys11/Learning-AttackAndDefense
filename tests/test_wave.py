import json
from pathlib import Path
from attnndef.attack.controller import SolverSpec, WaveController
from attnndef.attack.submitter import HttpSubmitter
from attnndef.core import Target, Role

def test_wave_controller_and_dry_submit(tmp_path):
    sink = None
    targets = [Target("enemy-1", "fixture", "127.0.0.1", 1, Role.ENEMY)]
    results, flags = WaveController([SolverSpec("fixture", "tests.fixture_solver:always_flag")], sink).run(targets)
    assert results[0].success and flags == ["FLAG{fixture-enemy-1}"]
    out = HttpSubmitter("http://127.0.0.1:9999/submit").submit(flags)
    assert not out[0].accepted and "DRY-RUN" in out[0].detail
