#!/usr/bin/env python3
"""Patched local-only command-injection teaching fixture."""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
import os, subprocess

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok\n"); return
        if parsed.path != "/ping":
            self.send_error(404); return
        host = parse_qs(parsed.query).get("host", [""])[0]
        if not host or len(host) > 120 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-" for c in host):
            self.send_error(400, "invalid host"); return
        out = subprocess.run(["printf", "%s", host], capture_output=True, text=True, timeout=1, check=False).stdout
        self.send_response(200); self.end_headers(); self.wfile.write(out.encode())
    def log_message(self, format, *args): pass

if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(os.environ.get("LAB_PORT", "18082"))), Handler).serve_forever()
