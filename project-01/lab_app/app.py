#!/usr/bin/env python3
"""
lab_app/app.py
Safe Localhost Demonstration Target Web Server.
GraySentinel Cyber Defence Lab — Day 1 Project 01
Candidate: Mrunal Urankar | Team: Red Team

This server is designed strictly for local demonstration and authorized lab testing.
It uses Python's built-in http.server to eliminate external dependencies.
"""

import argparse
import http.server
import json
import os
import socketserver
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_FILE = os.path.join(CURRENT_DIR, "templates", "index.html")


class SafeLabHandler(http.server.BaseHTTPRequestHandler):
    """Custom request handler implementing controlled lab routes and observable headers."""

    server_version = "Werkzeug/2.2.2"
    sys_version = "Python/3.10.12"

    def send_defense_headers(self, content_type: str = "text/html; charset=utf-8"):
        """Sends controlled security headers (mix of present and intentionally missing)."""
        self.send_header("Content-Type", content_type)
        # Configured defensive headers (demonstrates PRESENT)
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Set-Cookie", "session=eyJhZG1pbiI6ZmFsc2V9.Yw7n2w.9p_LAB_MOCK; HttpOnly; Path=/")
        # Intentionally OMITTED for educational observation:
        # - Content-Security-Policy (MISSING)
        # - Strict-Transport-Security (MISSING - plain HTTP lab)
        # - Permissions-Policy (MISSING)

    def do_OPTIONS(self):
        """Responds to safe HTTP method observation requests."""
        self.send_response(200)
        self.send_header("Allow", "GET, POST, HEAD, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        """Responds to HEAD request by sending headers without body."""
        self.send_response(200)
        self.send_defense_headers("text/html; charset=utf-8")
        self.send_header("Content-Length", "2698")
        self.end_headers()

    def do_POST(self):
        """Responds cleanly to simulated form/API submissions."""
        self.send_response(200)
        self.send_defense_headers("application/json")
        body = json.dumps({"status": "received", "message": "POST request acknowledged"}).encode("utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/")
        if not path:
            path = "/"

        # 1. Root landing
        if path == "/":
            self.send_response(200)
            self.send_defense_headers("text/html; charset=utf-8")
            if os.path.isfile(TEMPLATE_FILE):
                with open(TEMPLATE_FILE, "rb") as f:
                    body = f.read()
            else:
                body = b"<html><head><title>GraySentinel Lab Target</title></head><body><h1>Lab Target Active</h1></body></html>"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # 2. Authentication endpoint
        elif path == "/login":
            self.send_response(200)
            self.send_defense_headers("text/html; charset=utf-8")
            body = (
                b"<!DOCTYPE html><html><head><title>Login - GraySentinel Lab</title></head>"
                b"<body><h2>Candidate Authentication Portal</h2>"
                b"<form action='/login' method='POST'><input type='text' name='username'/><input type='password' name='password'/></form></body></html>"
            )
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # 3. Registration
        elif path == "/register":
            self.send_response(200)
            self.send_defense_headers("text/html; charset=utf-8")
            body = b"<!DOCTYPE html><html><head><title>Register</title></head><body><h2>Register New Account</h2></body></html>"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # 4. Logout / Dashboard redirects
        elif path in ("/logout", "/dashboard"):
            self.send_response(302)
            self.send_header("Location", "/login")
            self.send_defense_headers("text/plain")
            self.send_header("Content-Length", "0")
            self.end_headers()

        # 5. Administrative route (Restricted)
        elif path == "/admin":
            self.send_response(403)
            self.send_defense_headers("application/json")
            body = json.dumps({"error": "Forbidden", "detail": "Administrative privileges required."}).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # 6. REST API routes
        elif path == "/api":
            self.send_response(200)
            self.send_defense_headers("application/json")
            body = json.dumps({
                "name": "GraySentinel Cyber Defence Lab API",
                "version": "1.0.0",
                "status": "operational",
                "endpoints": ["/api/users", "/api/v1"]
            }).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path in ("/api/users", "/api/v1"):
            self.send_response(200)
            self.send_defense_headers("application/json")
            body = json.dumps({
                "users": [
                    {"id": 1, "username": "admin", "role": "lab_administrator"},
                    {"id": 2, "username": "mrunal_urankar", "role": "red_team_candidate"}
                ]
            }).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # 7. Robots.txt
        elif path == "/robots.txt":
            self.send_response(200)
            self.send_defense_headers("text/plain; charset=utf-8")
            content = (
                "User-agent: *\n"
                "Disallow: /admin\n"
                "Disallow: /dashboard\n"
                "Disallow: /api/\n"
                "Sitemap: http://127.0.0.1:5000/sitemap.xml\n"
            ).encode("utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        # 8. Sitemap.xml
        elif path == "/sitemap.xml":
            self.send_response(200)
            self.send_defense_headers("application/xml; charset=utf-8")
            content = (
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n"
                "  <url><loc>http://127.0.0.1:5000/</loc></url>\n"
                "  <url><loc>http://127.0.0.1:5000/login</loc></url>\n"
                "  <url><loc>http://127.0.0.1:5000/register</loc></url>\n"
                "</urlset>\n"
            ).encode("utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        # 9. Health & Uploads mock
        elif path in ("/health", "/status"):
            self.send_response(200)
            self.send_defense_headers("application/json")
            body = json.dumps({"status": "healthy", "service": "graysentinel-day1-lab"}).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/uploads":
            self.send_response(200)
            self.send_defense_headers("text/html; charset=utf-8")
            body = b"<html><body><h3>Uploads Index</h3><p>No user files exposed.</p></body></html>"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # 10. 404 Not Found
        else:
            self.send_response(404)
            self.send_defense_headers("text/html; charset=utf-8")
            body = b"<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, format: str, *args: any):
        """Custom clean logging to stdout."""
        sys.stdout.write(f"[LAB_SERVER] {self.address_string()} - {format % args}\n")
        sys.stdout.flush()


def run_lab(port: int = 5000, host: str = "127.0.0.1"):
    """Starts the safe local lab test server."""
    class ReusableTCPServer(socketserver.TCPServer):
        allow_reuse_address = True

    with ReusableTCPServer((host, port), SafeLabHandler) as httpd:
        print(f"[*] GraySentinel Safe Training Lab running at http://{host}:{port}/")
        print("[!] Press Ctrl+C to terminate.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down Safe Training Lab server.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GraySentinel Safe Training Target Web Server")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind (default: 5000)")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    cli_args = parser.parse_args()
    run_lab(port=cli_args.port, host=cli_args.host)
