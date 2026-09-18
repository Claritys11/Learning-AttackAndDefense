"""A trivial in-process 'service' fixture: reads a config file and, if it
contains a vulnerable marker, leaks a flag. Used only to exercise the
attack/defense pipeline end-to-end in tests -- not a real network service.
"""
from __future__ import annotations

from pathlib import Path

VULN_MARKER = "DEBUG=true"
FLAG = "FLAG{local_fixture_only}"


def write_vulnerable_config(path: Path) -> None:
    path.write_text(f"{VULN_MARKER}\nport=9000\n")


def attack_fn(target) -> str:
    """Stand-in exploit: 'attacking' just means reading the fixture's
    config and checking whether debug mode leaks the flag."""
    config_path = Path(target.metadata["config_path"])
    content = config_path.read_text() if config_path.exists() else ""
    if VULN_MARKER in content:
        return f"debug output: {FLAG}"
    return "debug output: (nothing sensitive)"


def check_fn(target) -> bool:
    """Health = config file exists and is parseable (has a port= line)."""
    config_path = Path(target.metadata["config_path"])
    if not config_path.exists():
        return False
    return "port=" in config_path.read_text()
