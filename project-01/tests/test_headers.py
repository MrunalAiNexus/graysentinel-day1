"""
tests/test_headers.py
Automated tests for security header analysis and observation reporting.
Covers:
  - Requirement 9: Missing security header
  - Requirement 10: Present security header
  - Scope Requirement: Clearly distinguishes observations from confirmed vulnerabilities
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.headers import analyze_security_headers


class TestSecurityHeaders(unittest.TestCase):
    """Test suite for HTTP defense-in-depth header observation."""

    def test_09_missing_security_headers(self):
        """Test 9: Correctly flags missing security headers and explains why it matters."""
        # Mock headers with zero defensive headers
        mock_headers = {
            "Server": "Apache/2.4.52",
            "Content-Type": "text/html; charset=utf-8",
            "Content-Length": "512"
        }

        result = analyze_security_headers(mock_headers, is_https=False)
        summary = result["summary"]

        self.assertEqual(summary["present_count"], 0)
        self.assertEqual(summary["missing_count"], 6)

        # Confirm CSP is classified as MISSING
        csp_finding = next(f for f in result["details"] if f["header"] == "Content-Security-Policy")
        self.assertEqual(csp_finding["status"], "MISSING")
        self.assertIsNotNone(csp_finding["why_it_matters"])
        self.assertIsNotNone(csp_finding["limitation_context"])

        # Confirm classification notice explicitly states observation status
        self.assertIn("NOT confirmed vulnerabilities", summary["classification_notice"])

    def test_10_present_security_headers(self):
        """Test 10: Correctly identifies present security headers with their values."""
        mock_headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer"
        }

        result = analyze_security_headers(mock_headers, is_https=True)
        summary = result["summary"]

        self.assertEqual(summary["present_count"], 4)
        self.assertEqual(summary["missing_count"], 2)

        xfo = next(f for f in result["details"] if f["header"] == "X-Frame-Options")
        self.assertEqual(xfo["status"], "PRESENT")
        self.assertEqual(xfo["value"], "DENY")
        self.assertIn("configured with value: 'DENY'", xfo["observation"])

    def test_10b_case_insensitive_header_lookup(self):
        """Test 10b: Header evaluation handles mixed/lowercase HTTP header casing."""
        mock_headers = {
            "x-frame-options": "SAMEORIGIN",
            "content-security-policy": "script-src 'self'"
        }
        result = analyze_security_headers(mock_headers)
        xfo = next(f for f in result["details"] if f["header"] == "X-Frame-Options")
        self.assertEqual(xfo["status"], "PRESENT")
        self.assertEqual(xfo["value"], "SAMEORIGIN")


if __name__ == "__main__":
    unittest.main()
