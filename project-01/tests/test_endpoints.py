"""
tests/test_endpoints.py
Automated tests for web endpoint enumeration logic, wordlist handling, and path categorization.
Covers:
  - Requirement 13: Endpoint found
  - Requirement 14: Endpoint not found
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.endpoints import (
    DEFAULT_ENDPOINT_LIST,
    categorize_endpoint,
    load_wordlist,
)


class TestEndpoints(unittest.TestCase):
    """Test suite for endpoint enumeration logic and categorization."""

    def test_13_endpoint_found_categorization(self):
        """Test 13: Correctly categorizes successfully discovered and protected endpoints."""
        self.assertEqual(categorize_endpoint("/login", 200), "Authentication")
        self.assertEqual(categorize_endpoint("/admin", 403), "Protected / Access Restricted")
        self.assertEqual(categorize_endpoint("/dashboard", 302), "Redirect")
        self.assertEqual(categorize_endpoint("/api/users", 200), "API Route")
        self.assertEqual(categorize_endpoint("/uploads", 200), "Accessible Resource")

    def test_14_endpoint_not_found_categorization(self):
        """Test 14: Correctly categorizes HTTP 404 Not Found."""
        self.assertEqual(categorize_endpoint("/nonexistent_path_xyz", 404), "Not Found")

    def test_wordlist_loader_defaults(self):
        """Test wordlist loader returns default safe list when None passed."""
        wl = load_wordlist(None)
        self.assertEqual(wl, DEFAULT_ENDPOINT_LIST)
        self.assertIn("/login", wl)
        self.assertIn("/robots.txt", wl)

    def test_wordlist_loader_custom_file(self):
        """Test wordlist loader properly cleans and normalizes custom paths from file."""
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".txt") as temp_file:
            temp_file.write("# Custom test paths\n")
            temp_file.write("admin\n")
            temp_file.write("/api/v1\n")
            temp_file.write("\n")
            temp_file.write("dashboard\n")
            temp_file.write("admin\n")  # duplicate
            temp_path = temp_file.name

        try:
            loaded = load_wordlist(temp_path)
            self.assertEqual(loaded, ["/admin", "/api/v1", "/dashboard"])
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


if __name__ == "__main__":
    unittest.main()
