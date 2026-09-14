"""
Tests for Project 01 Recon JSON parser and finding candidate generation.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure src directory is in sys.path
_src = Path(__file__).resolve().parent.parent / "src"
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

from gray_sentinel.parser import (
    load_recon_json,
    generate_candidate_findings,
    validate_recon_schema,
)
from gray_sentinel.errors import ReconParseError


class TestParser(unittest.TestCase):

    def setUp(self):
        self.valid_payload = {
            "target": "lab.graysentinel.internal",
            "scan_id": "GS-TEST-SCAN-01",
            "timestamp": "2026-09-14T10:00:00Z",
            "open_ports": [
                {"port": 80, "protocol": "tcp", "service": "http", "state": "open", "banner": "nginx/1.22.1"},
                {"port": 3306, "protocol": "tcp", "service": "mysql", "state": "open", "banner": "MySQL 8.0"},
            ],
            "endpoints": [
                {"path": "/", "status_code": 200, "method": "GET", "content_type": "text/html", "response_size": 1200},
                {"path": "/.env.bak", "status_code": 200, "method": "GET", "content_type": "text/plain", "response_size": 340},
                {"path": "/admin", "status_code": 200, "method": "GET", "content_type": "text/html", "response_size": 2100},
            ],
            "missing_security_headers": [
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Frame-Options",
                "X-Content-Type-Options",
            ],
            "is_demo": True,
        }

    def test_load_recon_json_success(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as f:
            json.dump(self.valid_payload, f)
            temp_path = f.name

        try:
            recon = load_recon_json(temp_path)
            self.assertEqual(recon.target, "lab.graysentinel.internal")
            self.assertEqual(recon.scan_id, "GS-TEST-SCAN-01")
            self.assertEqual(len(recon.open_ports), 2)
            self.assertEqual(len(recon.endpoints), 3)
            self.assertEqual(len(recon.missing_security_headers), 4)
            self.assertTrue(recon.is_demo)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_load_recon_json_file_not_found(self):
        with self.assertRaises(ReconParseError) as ctx:
            load_recon_json("/tmp/non_existent_recon_file_xyz123.json")
        self.assertIn("not found", str(ctx.exception).lower())

    def test_load_recon_json_malformed(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as f:
            f.write("{ invalid json formatting ... ")
            temp_path = f.name

        try:
            with self.assertRaises(ReconParseError) as ctx:
                load_recon_json(temp_path)
            self.assertIn("malformed json", str(ctx.exception).lower())
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_load_recon_json_missing_keys(self):
        invalid_data = {"target": "lab.internal"}  # missing scan_id, timestamp, etc.
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as f:
            json.dump(invalid_data, f)
            temp_path = f.name

        try:
            with self.assertRaises(ReconParseError) as ctx:
                load_recon_json(temp_path)
            self.assertIn("missing required keys", str(ctx.exception).lower())
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_generate_candidate_findings_correlation(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as f:
            json.dump(self.valid_payload, f)
            temp_path = f.name

        try:
            recon = load_recon_json(temp_path)
            candidates = generate_candidate_findings(recon)
            self.assertGreater(len(candidates), 0)

            # Check that missing headers finding was generated
            header_findings = [c for c in candidates if "headers" in c.title.lower()]
            self.assertEqual(len(header_findings), 1)

            # Check that sensitive config finding was generated (.env.bak)
            env_findings = [c for c in candidates if ".env.bak" in c.affected_asset]
            self.assertEqual(len(env_findings), 1)
            self.assertEqual(env_findings[0].severity.value, "CRITICAL")

            # Check database port finding was generated (3306)
            db_findings = [c for c in candidates if "3306" in c.affected_asset]
            self.assertEqual(len(db_findings), 1)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


if __name__ == "__main__":
    unittest.main()
