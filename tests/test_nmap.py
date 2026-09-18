from attnndef.integrations.nmap import parse_nmap_xml, validate_ports
import pytest

def test_parse_nmap_xml_normalizes_services():
    raw = '''<nmaprun><host><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH"/></port><port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port></ports></host></nmaprun>'''
    services = parse_nmap_xml(raw)
    assert services[0].port == 22
    assert services[0].name == "ssh"
    assert services[0].version == "OpenSSH"

def test_parse_empty_nmap_xml():
    assert parse_nmap_xml("") == ()

def test_validate_ports_accepts_only_port_specs():
    assert validate_ports("22,80,8000-8010") == "22,80,8000-8010"
    for value in ["--script vuln", "0", "65536", "100-10", "80;id"]:
        with pytest.raises(ValueError): validate_ports(value)
