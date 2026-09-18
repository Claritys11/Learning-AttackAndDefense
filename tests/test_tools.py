import os
import sys
import tempfile
import pytest

from attnndef.integrations.tool_runner import ToolResult, ToolRunner
from attnndef.tools import (
    DiscoveredHost,
    FfufAdapter,
    FfufMatch,
    FfufScanResult,
    FfufService,
    GdbAdapter,
    GdbService,
    HttpAdapter,
    HttpRequest,
    HttpResponse,
    HttpService,
    NmapAdapter,
    NmapService,
    SshAdapter,
    SshService,
    SystemAdapter,
    SystemService,
    TcpdumpAdapter,
    TcpdumpService,
    parse_discovery_xml,
    parse_ffuf_json,
    parse_http_raw,
    parse_nmap_xml,
    validate_ports,
)

class FakeToolRunner:
    def __init__(self, stdout="", stderr="", returncode=0, timed_out=False, error_kind="success"):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.timed_out = timed_out
        self.error_kind = error_kind
        self.last_command = None
        self.last_timeout = None

    def run(self, command, *, timeout_s=10.0, cwd=None, input=None):
        self.last_command = tuple(command)
        self.last_timeout = timeout_s
        return ToolResult(
            command=self.last_command,
            returncode=self.returncode,
            stdout=self.stdout,
            stderr=self.stderr,
            started_at=100.0,
            finished_at=100.5,
            timed_out=self.timed_out,
            error_kind=self.error_kind,
        )

def test_tool_runner_error_kinds_and_success():
    res_ok = ToolResult(("test",), 0, "ok", "", 1.0, 1.2, error_kind="success")
    assert res_ok.success
    assert res_ok.duration == pytest.approx(0.2)

    res_fail = ToolResult(("test",), 1, "", "err", 1.0, 1.2, error_kind="nonzero_exit")
    assert not res_fail.success
    assert res_fail.error_kind == "nonzero_exit"

    res_timeout = ToolResult(("test",), None, "", "timed out", 1.0, 2.0, timed_out=True, error_kind="timeout")
    assert not res_timeout.success
    assert res_timeout.timed_out
    assert res_timeout.error_kind == "timeout"

def test_nmap_adapter_and_service():
    xml_discovery = """<nmaprun>
    <host><address addr="10.10.1.5"/><status state="up"/></host>
    <host><address addr="10.10.1.6"/><status state="down"/></host>
    </nmaprun>"""
    runner = FakeToolRunner(stdout=xml_discovery)
    adapter = NmapAdapter(runner)
    svc = NmapService(adapter)

    hosts = svc.discover("10.10.1.0/24")
    assert len(hosts) == 2
    assert hosts[0].host == "10.10.1.5"
    assert hosts[0].status == "up"
    assert hosts[1].host == "10.10.1.6"
    assert "-sn" in runner.last_command

    xml_ports = """<nmaprun>
    <host><ports>
        <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/></port>
        <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH"/></port>
    </ports></host></nmaprun>"""
    runner.stdout = xml_ports
    services = svc.scan_target("10.10.1.5", ports="22,80", service_detection=True)
    assert len(services) == 2
    assert services[0].port == 80
    assert services[0].name == "http"
    assert "-sV" in runner.last_command
    assert "-sC" in runner.last_command

def test_http_adapter_and_service():
    raw_http = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nServer: gunicorn\r\n\r\n{\"status\": \"healthy\"}"
    status, headers, body = parse_http_raw(raw_http)
    assert status == 200
    assert headers["content-type"] == "application/json"
    assert headers["server"] == "gunicorn"
    assert "{\"status\": \"healthy\"}" in body

    runner = FakeToolRunner(stdout=raw_http)
    adapter = HttpAdapter(runner)
    svc = HttpService(adapter)

    resp = svc.get("http://example.com/health")
    assert resp.status_code == 200
    assert resp.headers["server"] == "gunicorn"
    assert "curl" in runner.last_command[0]
    assert "-X" in runner.last_command
    assert "GET" in runner.last_command

    post_resp = svc.post("http://example.com/api", body='{"key":"val"}', headers={"Authorization": "Bearer token"})
    assert post_resp.status_code == 200
    assert "POST" in runner.last_command
    assert "--data-binary" in runner.last_command
    assert "-H" in runner.last_command
    assert "--" in runner.last_command

    with pytest.raises(ValueError, match="start with a hyphen"):
        adapter.execute(HttpRequest(url="-v"))
    with pytest.raises(ValueError, match="empty"):
        adapter.execute(HttpRequest(url="  "))

def test_integration_delegation_to_canonical_tools():
    from attnndef.integrations.nmap import parse_nmap_xml as integ_parse, validate_ports as integ_val
    from attnndef.tools.nmap import parse_nmap_xml as tool_parse, validate_ports as tool_val
    assert integ_parse is tool_parse
    assert integ_val is tool_val

    from attnndef.integrations.discovery import DiscoveredHost as integ_host, parse_discovery_xml as integ_disc
    from attnndef.tools.nmap import DiscoveredHost as tool_host, parse_discovery_xml as tool_disc
    assert integ_host is tool_host
    assert integ_disc is tool_disc


def test_ffuf_adapter_and_service():
    sample_json = """{
      "results": [
        {"url": "http://target/admin", "status": 200, "length": 512, "words": 40, "lines": 15, "redirectlocation": ""},
        {"url": "http://target/login", "status": 302, "length": 0, "words": 0, "lines": 0, "redirectlocation": "/auth"}
      ]
    }"""
    matches = parse_ffuf_json(sample_json)
    assert len(matches) == 2
    assert matches[0].url == "http://target/admin"
    assert matches[0].status == 200
    assert matches[1].redirect_location == "/auth"

    runner = FakeToolRunner(stdout=sample_json)
    adapter = FfufAdapter(runner)
    svc = FfufService(adapter)

    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write("admin\nlogin\n")
        w_path = f.name

    try:
        res = svc.discover_endpoints("http://127.0.0.1", w_path)
        assert len(res.matches) == 2
        assert "ffuf" in runner.last_command[0]
        assert "-u" in runner.last_command
    finally:
        if os.path.exists(w_path):
            os.remove(w_path)

def test_ssh_adapter_and_service():
    runner = FakeToolRunner(stdout="Linux target 5.15.0\n", returncode=0)
    adapter = SshAdapter(runner)
    svc = SshService(adapter)

    res = svc.run("10.0.0.5", "uname -a", port=2222, username="ctf", identity_file="/tmp/id_rsa")
    assert res.returncode == 0
    assert "Linux target" in res.stdout
    assert "-p" in runner.last_command
    assert "2222" in runner.last_command
    assert "-i" in runner.last_command
    assert "ctf@10.0.0.5" in runner.last_command
    assert "uname -a" in runner.last_command

    with pytest.raises(ValueError):
        svc.run("", "uname -a")
    with pytest.raises(ValueError):
        svc.run("10.0.0.5", "")

def test_tcpdump_adapter_and_service():
    sample_out = "12:00:00.000 IP 10.0.0.1.1234 > 10.0.0.2.80: Flags [S], seq 1"
    runner = FakeToolRunner(stdout=sample_out)
    adapter = TcpdumpAdapter(runner)
    svc = TcpdumpService(adapter)

    res = svc.capture_live(interface="eth0", duration_s=2.0, packet_count=10, bpf_filter="tcp port 80")
    assert res.interface == "eth0"
    assert res.packet_count == 10
    assert "tcpdump" in runner.last_command[0]
    assert "-i" in runner.last_command
    assert "eth0" in runner.last_command
    assert "-c" in runner.last_command
    assert "10" in runner.last_command
    assert "tcp port 80" in runner.last_command

    with pytest.raises(ValueError):
        adapter.capture(duration_s=0)
    with pytest.raises(ValueError):
        adapter.capture(packet_count=0)

def test_gdb_adapter_and_service():
    runner = FakeToolRunner(stdout="Dump of assembler code for function main:\n   0x0000000000401126 <+0>: push %rbp\n")
    adapter = GdbAdapter(runner)
    svc = GdbService(adapter)

    # Use sys.executable as existing binary for path check
    res = svc.inspect_binary(sys.executable)
    assert "disassemble main" in runner.last_command
    assert "--batch" in runner.last_command
    assert "push %rbp" in res.stdout

    with pytest.raises(FileNotFoundError):
        svc.inspect_binary("/path/to/nonexistent/binary/xyz123")

def test_system_adapter_and_service():
    runner = FakeToolRunner(stdout="10.0.0.2 dev wg0\n")
    adapter = SystemAdapter(runner)
    svc = SystemService(adapter)

    res_ss = svc.ss_listening()
    assert runner.last_command == ("ss", "-tulpn")

    res_ps = svc.ps_aux()
    assert runner.last_command == ("ps", "aux")

    res_systemctl = svc.systemctl_status("nginx")
    assert runner.last_command == ("systemctl", "status", "nginx", "--no-pager")

    res_ip = svc.ip_addr()
    assert runner.last_command == ("ip", "addr")

    res_dig = svc.dig_lookup("jjz.jatimprov.go.id")
    assert runner.last_command == ("dig", "+short", "jjz.jatimprov.go.id", "A")

    res_wg = svc.wireguard_status("wg0")
    assert runner.last_command == ("wg", "show", "wg0")
