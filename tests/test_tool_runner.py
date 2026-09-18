import sys
import pytest
from attnndef.integrations import ToolRunner

def test_runner_captures_output():
    result = ToolRunner().run([sys.executable, "-c", "print('ok')"], timeout_s=2)
    assert result.success
    assert result.stdout.strip() == "ok"

def test_runner_terminates_timeout():
    result = ToolRunner().run([sys.executable, "-c", "import time; time.sleep(5)"], timeout_s=0.05)
    assert result.timed_out
    assert result.returncode is not None
    assert "process group" in result.stderr

def test_runner_normalizes_missing_binary():
    result = ToolRunner().run(["definitely-not-a-real-binary"], timeout_s=1)
    assert result.error_kind == "not_found"
    assert not result.success

def test_runner_rejects_empty_argument():
    with pytest.raises(ValueError):
        ToolRunner().run([sys.executable, ""])
