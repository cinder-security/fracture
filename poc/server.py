#!/usr/bin/env python3
"""
Local logging server for prompt injection PoC.
Captures and displays incoming requests to /log.

Usage:
    python server.py
    # Listens on http://localhost:8080
"""

import json
import urllib.parse
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer


class LogHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/log":
            params = urllib.parse.parse_qs(parsed.query)
            self._record("GET", params)
            self._respond(200, {"status": "logged"})
        else:
            self._respond(404, {"error": "not found"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/log":
            length = int(self.headers.get("Content-Length", 0))
            body_raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(body_raw)
            except Exception:
                body = {"raw": body_raw.decode(errors="replace")}
            self._record("POST", body)
            self._respond(200, {"status": "logged"})
        else:
            self._respond(404, {"error": "not found"})

    def do_OPTIONS(self):
        # Allow CORS preflight so browser/agent fetch() calls succeed
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def _record(self, method, data):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src = f"{self.client_address[0]}:{self.client_address[1]}"
        print("\n" + "=" * 60)
        print(f"[{ts}]  {method} /log  from {src}")
        print(f"User-Agent : {self.headers.get('User-Agent', '-')}")
        print(f"Referer    : {self.headers.get('Referer', '-')}")
        print(f"Data       : {json.dumps(data, ensure_ascii=False, indent=2)}")
        print("=" * 60)

    def _respond(self, code, body):
        payload = json.dumps(body).encode()
        self.send_response(code)
        self._cors_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def log_message(self, fmt, *args):
        pass  # suppress default Apache-style access log


if __name__ == "__main__":
    host, port = "127.0.0.1", 8080
    server = HTTPServer((host, port), LogHandler)
    print(f"Logging server running → http://{host}:{port}/log")
    print("Waiting for requests (Ctrl+C to stop)...\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
