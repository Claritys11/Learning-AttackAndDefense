#!/usr/bin/env python3
"""Bounded local reproduction for Lab 02."""
import argparse, urllib.request

p = argparse.ArgumentParser()
p.add_argument("--base", default="http://127.0.0.1:18082")
p.add_argument("--expect", choices=["vulnerable", "patched"], default="vulnerable")
a = p.parse_args()
normal = urllib.request.urlopen(a.base + "/ping?host=localhost", timeout=2).read().decode()
probe = urllib.request.urlopen(a.base + "/ping?host=hello%3Bprintf%20INJECTED", timeout=2).read().decode()
assert normal == "localhost", normal
if a.expect == "vulnerable":
    assert "INJECTED" in probe, repr(probe)
else:
    import urllib.error
    try:
        urllib.request.urlopen(a.base + "/ping?host=hello%3Bprintf%20INJECTED", timeout=2)
    except urllib.error.HTTPError as exc:
        assert exc.code == 400, exc.code
    else:
        raise AssertionError("patched mode accepted the shell metacharacter")
print("PASS: normal flow and local reproduction")
