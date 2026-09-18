import json
import sys
import tempfile
import pytest
from unittest.mock import patch

from attnndef.cli import main
from attnndef.integrations.tool_runner import ToolResult

class FakeRunner:
    def __init__(self, stdout="", stderr="", returncode=0, timed_out=False, error_kind="success"):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.timed_out = timed_out
        self.error_kind = error_kind
        self.last_command = None

    def run(self, command, *, timeout_s=10.0, cwd=None, input=None):
        self.last_command = tuple(command)
        return ToolResult(
            command=self.last_command,
            returncode=self.returncode,
            stdout=self.stdout,
            stderr=self.stderr,
            started_at=10.0,
            finished_at=10.2,
            timed_out=self.timed_out,
            error_kind=self.error_kind,
        )

def test_cli_nmap_discover_and_scan(capsys):
    xml_discovery = '<nmaprun><host><address addr="10.10.1.5"/><status state="up"/></host></nmaprun>'
    runner = FakeRunner(stdout=xml_discovery)
    with patch("attnndef.cli.ToolRunner", return_value=runner):
        ret = main(["nmap", "--discover", "10.10.1.0/24", "--json"])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 1
        assert data[0]["host"] == "10.10.1.5"

    xml_ports = '<nmaprun><host><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/></port></ports></host></nmaprun>'
    runner.stdout = xml_ports
    with patch("attnndef.cli.ToolRunner", return_value=runner):
        ret = main(["nmap", "--host", "10.10.1.5", "--ports", "80", "--json"])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 1
        assert data[0]["port"] == 80

def test_cli_http_request(capsys):
    raw_http = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOK"
    runner = FakeRunner(stdout=raw_http)
    with patch("attnndef.cli.ToolRunner", return_value=runner):
        ret = main(["http", "--url", "http://127.0.0.1:8080/health", "--json"])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status_code"] == 200
        assert data["body"] == "OK"

def test_cli_ffuf_discovery(capsys):
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write("admin\n")
        w_path = f.name
    sample_json = '{"results": [{"url": "http://target/admin", "status": 200, "length": 512, "words": 40, "lines": 15, "redirectlocation": ""}]}'
    runner = FakeRunner(stdout=sample_json)
    with patch("attnndef.cli.ToolRunner", return_value=runner):
        ret = main(["ffuf", "--url", "http://target/FUZZ", "--wordlist", w_path, "--json"])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data["matches"]) == 1
        assert data["matches"][0]["status"] == 200

def test_cli_ssh_and_tcpdump(capsys):
    runner_ssh = FakeRunner(stdout="Linux target\n")
    with patch("attnndef.cli.ToolRunner", return_value=runner_ssh):
        ret = main(["ssh", "--host", "10.0.0.5", "--command", "uname -a", "--json"])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["returncode"] == 0
        assert "Linux target" in data["stdout"]

    runner_tcp = FakeRunner(stdout="12:00:00 IP A > B\n")
    with patch("attnndef.cli.ToolRunner", return_value=runner_tcp):
        ret = main(["tcpdump", "--interface", "eth0", "--count", "5", "--json"])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "12:00:00" in data["raw_output"]

def test_cli_gdb_and_sys(capsys):
    runner_gdb = FakeRunner(stdout="disassembly\n")
    with patch("attnndef.cli.ToolRunner", return_value=runner_gdb):
        ret = main(["gdb", "--binary", sys.executable, "--op", "inspect", "--json"])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "disassembly" in data["stdout"]

    runner_sys = FakeRunner(stdout="LISTEN 0 128 0.0.0.0:80\n")
    with patch("attnndef.cli.ToolRunner", return_value=runner_sys):
        ret = main(["sys", "--op", "ss-listen", "--json"])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "LISTEN" in data["stdout"]
