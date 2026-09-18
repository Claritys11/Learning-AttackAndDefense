import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from attnndef.core.models import Role, Target  # noqa: E402
from tests.fixtures.mock_service import write_vulnerable_config  # noqa: E402


@pytest.fixture
def tmp_config(tmp_path) -> Path:
    cfg = tmp_path / "service.ini"
    write_vulnerable_config(cfg)
    return cfg


@pytest.fixture
def own_target(tmp_config) -> Target:
    return Target(
        id="svc-own-01",
        name="own-web",
        host="127.0.0.1",
        port=8001,
        role=Role.OWN,
        tags=("web",),
        metadata={"config_path": str(tmp_config)},
    )
