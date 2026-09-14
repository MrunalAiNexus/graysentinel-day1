"""
tests/test_target.py
Automated tests for target parsing, syntax validation, and authorization scope.
Covers:
  - Requirement 1: Valid target
  - Requirement 2: Invalid target
  - Requirement 3: Unreachable target / Scope restriction
"""

import sys
import unittest
import os

# Add parent project-01 directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.target import (
    TargetValidationError,
    is_lab_hostname,
    is_private_or_lab_ip,
    parse_and_validate_target,
)


class TestTargetValidation(unittest.TestCase):
    """Test suite for target input validation and authorization checks."""

    def test_01_valid_localhost_target(self):
        """Test 1: Valid target parsing with explicit port."""
        target = "http://127.0.0.1:5000"
        result = parse_and_validate_target(target)
        self.assertEqual(result["hostname"], "127.0.0.1")
        self.assertEqual(result["port"], 5000)
        self.assertEqual(result["protocol"], "http")
        self.assertTrue(result["is_lab_scope"])
        self.assertEqual(result["authorization_status"], "AUTHORIZED_LAB_TARGET")

    def test_02_valid_rfc1918_private_target(self):
        """Test 1b: Valid RFC 1918 private lab target without protocol specified."""
        target = "192.168.56.101"
        result = parse_and_validate_target(target)
        self.assertEqual(result["hostname"], "192.168.56.101")
        self.assertEqual(result["port"], 80)
        self.assertEqual(result["protocol"], "http")
        self.assertTrue(result["is_lab_scope"])

    def test_03_invalid_empty_target(self):
        """Test 2a: Empty or whitespace target raises TargetValidationError."""
        with self.assertRaises(TargetValidationError):
            parse_and_validate_target("")

    def test_04_invalid_protocol(self):
        """Test 2b: Disallowed protocol (e.g. ftp, gopher) raises TargetValidationError."""
        with self.assertRaises(TargetValidationError):
            parse_and_validate_target("ftp://127.0.0.1:21")

    def test_05_invalid_port_range(self):
        """Test 2c: Port out of range raises TargetValidationError."""
        with self.assertRaises(TargetValidationError):
            parse_and_validate_target("http://127.0.0.1:999999")

    def test_06_unreachable_or_unresolvable_hostname(self):
        """Test 3a: Non-existent hostname resolution fails safely."""
        with self.assertRaises(TargetValidationError):
            parse_and_validate_target("http://non-existent-lab-domain-xyz-12345.local")

    def test_07_unauthorized_external_ip_rejected_without_flag(self):
        """Test 3b: Arbitrary external public IP rejected unless explicitly authorized."""
        # 8.8.8.8 is a public IP, outside RFC 1918 private scope
        with self.assertRaises(TargetValidationError) as ctx:
            parse_and_validate_target("http://8.8.8.8", allow_external=False)
        self.assertIn("not a recognized private/lab target", str(ctx.exception))

    def test_08_authorized_external_target_with_flag(self):
        """Test 3c: Target accepted when user explicitly confirms authorization."""
        result = parse_and_validate_target("http://8.8.8.8", allow_external=True)
        self.assertEqual(result["resolved_ip"], "8.8.8.8")
        self.assertEqual(result["authorization_status"], "AUTHORIZED_EXPLICIT_TARGET")


if __name__ == "__main__":
    unittest.main()
