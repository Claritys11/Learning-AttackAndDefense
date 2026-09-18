import json

import pytest

from attnndef.core.errors import TargetNotFoundError
from attnndef.core.models import Role
from attnndef.core.registry import TargetRegistry


def test_from_file_and_filter(tmp_path):
    cfg = tmp_path / "targets.json"
    cfg.write_text(
        json.dumps(
            {
                "targets": [
                    {"id": "a", "host": "127.0.0.1", "port": 1, "role": "own", "tags": ["web"]},
                    {"id": "b", "host": "127.0.0.1", "port": 2, "role": "enemy", "tags": ["web"]},
                ]
            }
        )
    )
    reg = TargetRegistry.from_file(cfg)
    assert len(reg.all()) == 2
    assert [t.id for t in reg.filter(role=Role.OWN)] == ["a"]
    assert reg.get("b").role == Role.ENEMY
    with pytest.raises(TargetNotFoundError):
        reg.get("missing")
