#!/usr/bin/env python3
"""Bounded local reproduction for Lab 02."""
import argparse, urllib.request

p = argparse.ArgumentParser()
p.add_argument("--base", default="http://127.0.0.1:18082")
p.add_argument("--expect", choices=["vulnerable", "patched"], default="vulnerable")
a = p.parse_args()
normal = urllib.request.urlopen(a.base + "/ping?host=localhost", timeout=2).read().decode()
assert normal == "localhost", normal
import urllib.error
try:
    probe = urllib.request.urlopen(a.base + "/ping?host=hello%3Bprintf%20INJECTED", timeout=2).read().decode()
except urllib.error.HTTPError as exc:
    if a.expect != "patched" or exc.code != 400:
        raise
else:
    if a.expect != "vulnerable" or "INJECTED" not in probe:
        raise AssertionError("unexpected shell-marker response")
print("PASS: normal flow and local reproduction")
