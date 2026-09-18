#!/usr/bin/env python3
"""Local-only command-injection teaching fixture; never expose this server."""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
import os, subprocess

FLAG = os.environ.get("LAB_FLAG", "FLAG{local-command-injection}")
PATCHED = os.environ.get("LAB_PATCHED", "0") == "1"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        if urlparse(self.path).path == "/health":
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok\n"); return
        if urlparse(self.path).path != "/ping":
            self.send_error(404); return
        host = q.get("host", [""])[0]
        if not host or len(host) > 120:
            self.send_error(400, "host required"); return
        try:
            if PATCHED:
                out = subprocess.run(["printf", "%s", host], capture_output=True, text=True, timeout=1, check=False).stdout
            else:
                out = subprocess.run("printf " + host, shell=True, capture_output=True, text=True, timeout=1, check=False).stdout
            body = out.encode()
            self.send_response(200); self.end_headers(); self.wfile.write(body)
        except subprocess.TimeoutExpired:
            self.send_error(408)
    def log_message(self, format, *args): pass

if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(os.environ.get("LAB_PORT", "18082"))), Handler).serve_forever()
