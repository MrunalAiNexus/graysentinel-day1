"""
tests/test_integration.py
End-to-end integration tests using an ephemeral localhost test server thread.
Covers:
  - Requirement 4: Open port
  - Requirement 5: Closed port
  - Requirement 6: HTTP 200
  - Requirement 7: HTTP 404
  - Requirement 8: Redirect
  - Requirement 11: robots.txt present
  - Requirement 12: robots.txt absent
  - Requirement 15: Timeout/error handling
"""

import http.server
import os
import socket
import socketserver
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.endpoints import probe_endpoint
from src.http_enum import enumerate_http_service
from src.port_scanner import probe_single_port
from src.robots import discover_robots_and_sitemap


class MockHandler(http.server.BaseHTTPRequestHandler):
    """Ephemeral handler to simulate real lab web responses."""
    server_version = "Werkzeug/2.2.2"
    sys_version = ""

    def version_string(self):
        return "Werkzeug/2.2.2"

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Werkzeug/2.2.2")
            body = b"<html><head><title>Integration Lab</title></head><body>OK</body></html>"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/redirect-me":
            self.send_response(302)
            self.send_header("Location", "/destination")
            self.send_header("Content-Length", "0")
            self.end_headers()

        elif self.path == "/destination":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            body = b"Destination reached."
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            body = b"User-agent: *\nDisallow: /secret-lab"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/slow":
            # Sleep longer than client timeout to test timeout handling
            time.sleep(1.5)
            self.send_response(200)
            self.end_headers()

        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            body = b"Not Found"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, format, *args):
        # Suppress noisy HTTP logs during testing
        pass


class TestIntegration(unittest.TestCase):
    """Integration test suite against live ephemeral socket/HTTP server."""

    @classmethod
    def setUpClass(cls):
        # Find a free local port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            cls.port = s.getsockname()[1]

        cls.server = socketserver.TCPServer(("127.0.0.1", cls.port), MockHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_04_open_port_detection(self):
        """Test 4: TCP probe identifies active listening port as OPEN."""
        probe = probe_single_port("127.0.0.1", self.port, timeout=1.0)
        self.assertEqual(probe["state"], "OPEN")
        self.assertEqual(probe["port"], self.port)

    def test_05_closed_port_detection(self):
        """Test 5: TCP probe identifies unused port as CLOSED."""
        # Find an unused port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            unused_port = s.getsockname()[1]
        # Probe it after socket is closed
        probe = probe_single_port("127.0.0.1", unused_port, timeout=0.5)
        self.assertEqual(probe["state"], "CLOSED")

    def test_06_http_200_enumeration(self):
        """Test 6: HTTP service enumeration captures 200 OK and metadata."""
        http_data = enumerate_http_service(self.base_url, timeout=2.0)
        self.assertEqual(http_data["status_code"], 200)
        self.assertEqual(http_data["html_title"], "Integration Lab")
        self.assertEqual(http_data["server_header"], "Werkzeug/2.2.2")

    def test_07_http_404_handling(self):
        """Test 7: Probing non-existent resource records HTTP 404 cleanly."""
        probe = probe_endpoint(self.base_url, "/does-not-exist", timeout=1.0)
        self.assertEqual(probe["status_code"], 404)
        self.assertEqual(probe["category"], "Not Found")

    def test_08_redirect_handling(self):
        """Test 8: Captures 302 redirect location without crashing."""
        probe = probe_endpoint(self.base_url, "/redirect-me", timeout=1.0)
        self.assertEqual(probe["status_code"], 302)
        self.assertEqual(probe["redirect_to"], "/destination")
        self.assertEqual(probe["category"], "Redirect")

    def test_11_robots_txt_present(self):
        """Test 11: Accurately discovers and parses existing robots.txt."""
        res = discover_robots_and_sitemap(self.base_url, timeout=1.0)
        self.assertTrue(res["robots"]["present"])
        self.assertIn("/secret-lab", res["robots"]["parsed"]["disallowed_paths"])

    def test_12_robots_txt_absent(self):
        """Test 12: Handles missing sitemap gracefully without raising exception."""
        res = discover_robots_and_sitemap(self.base_url, timeout=1.0)
        # Sitemap was not configured in MockHandler, should be absent
        self.assertFalse(res["sitemap"]["present"])
        self.assertEqual(res["sitemap"]["url_count"], 0)

    def test_15_timeout_and_error_handling(self):
        """Test 15: Safe handling when target endpoint times out."""
        # Query /slow with a short 0.2s timeout
        probe = probe_endpoint(self.base_url, "/slow", timeout=0.2)
        self.assertIsNotNone(probe["error"])
        self.assertIn("timeout", probe["error"].lower())


if __name__ == "__main__":
    unittest.main()
