"""
tests/test_output.py
Automated tests for structured JSON serialization and human-readable text generation.
Covers:
  - Requirement 16: JSON output generation
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.output import build_json_report, build_text_report, write_reports


class TestOutputGeneration(unittest.TestCase):
    """Test suite for structured report serialization."""

    def setUp(self):
        self.sample_data = {
            "metadata": {
                "candidate": "Mrunal Urankar",
                "team": "Red Team",
                "project": "Project 01 — Authorized Web Recon & Enumeration"
            },
            "target": {
                "normalized_url": "http://127.0.0.1:5000",
                "hostname": "127.0.0.1",
                "resolved_ip": "127.0.0.1",
                "protocol": "http",
                "port": 5000,
                "authorization_status": "AUTHORIZED_LAB_TARGET"
            },
            "network": {
                "open_ports_count": 1,
                "ports": [
                    {"port": 5000, "state": "OPEN", "service": "Flask / Python Web App", "latency_ms": 1.2}
                ]
            },
            "web": {
                "status_code": 200,
                "status_message": "OK",
                "response_time_ms": 5.4,
                "server_header": "Werkzeug/2.2.2 Python/3.10.12",
                "content_type": "text/html; charset=utf-8",
                "content_length": 1024,
                "final_url": "http://127.0.0.1:5000",
                "redirect_count": 0
            },
            "http_methods": {
                "allowed_methods": ["GET", "POST", "HEAD", "OPTIONS"]
            },
            "headers": {
                "summary": {"present_count": 2, "missing_count": 4},
                "details": [
                    {
                        "header": "X-Frame-Options",
                        "status": "PRESENT",
                        "observation": "Header is configured with value: 'SAMEORIGIN'",
                        "why_it_matters": "Prevents Clickjacking",
                        "limitation_context": "Safe context"
                    }
                ]
            },
            "technologies": [
                {"name": "Flask", "category": "Python Web Framework", "confidence": "Medium", "evidence": "Werkzeug"}
            ],
            "robots": {"present": True, "parsed": {"disallowed_paths": ["/admin"]}},
            "sitemap": {"present": True, "url_count": 3},
            "endpoints": {
                "wordlist_size": 5,
                "discovered_count": 3,
                "endpoints": [
                    {"path": "/login", "status_code": 200, "category": "Authentication", "content_length": 250}
                ]
            },
            "timestamp": "2026-09-14T10:00:00Z"
        }

    def test_16_json_report_generation(self):
        """Test 16: Verifies that JSON output is valid, structured, and contains all required root keys."""
        json_str = build_json_report(self.sample_data)
        parsed = json.loads(json_str)

        # Verify root schema keys per specification
        required_keys = ["target", "network", "web", "headers", "technologies", "endpoints", "robots", "sitemap", "timestamp"]
        for key in required_keys:
            self.assertIn(key, parsed, f"Missing required root key: {key}")

        self.assertEqual(parsed["target"]["hostname"], "127.0.0.1")
        self.assertEqual(parsed["web"]["status_code"], 200)

    def test_text_report_generation(self):
        """Test text report builds properly formatted string with section markers."""
        text_str = build_text_report(self.sample_data)
        self.assertIn("GRAYSENTINEL CYBER DEFENCE LAB", text_str)
        self.assertIn("TARGET IDENTIFICATION", text_str)
        self.assertIn("SECURITY HEADER ANALYSIS", text_str)
        self.assertIn("Mrunal Urankar", text_str)

    def test_file_writing(self):
        """Test that write_reports creates actual recon.json and recon.txt on disk."""
        with tempfile.TemporaryDirectory() as temp_dir:
            written = write_reports(self.sample_data, output_dir=temp_dir)
            self.assertTrue(os.path.isfile(written["json_path"]))
            self.assertTrue(os.path.isfile(written["text_path"]))
            self.assertGreater(os.path.getsize(written["json_path"]), 0)
            self.assertGreater(os.path.getsize(written["text_path"]), 0)


if __name__ == "__main__":
    unittest.main()
