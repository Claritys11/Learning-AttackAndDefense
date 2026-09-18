import sys
from attnndef.integrations import ToolRunner

def test_runner_captures_output():
    result = ToolRunner().run([sys.executable, "-c", "print('ok')"], timeout_s=2)
    assert result.returncode == 0
    assert result.stdout.strip() == "ok"
    assert not result.timed_out

def test_runner_terminates_timeout():
    result = ToolRunner().run([sys.executable, "-c", "import time; time.sleep(5)"], timeout_s=0.05)
    assert result.timed_out
    assert result.returncode is not None
    assert "timeout" in result.stderr
