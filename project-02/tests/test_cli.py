"""
Tests for GraySentinel CLI: argument parsing, commands, and exit behavior.
"""

import os
import subprocess
import sys
import unittest
from pathlib import Path

# Resolve paths dynamically relative to test file so tests pass from any CWD
PROJECT_ROOT = Path(__file__).resolve().parent.parent
MAIN_PY = str(PROJECT_ROOT / "main.py")
INVALID_SAMPLE = str(PROJECT_ROOT / "data" / "invalid_finding_sample.json")
SRC_DIR = str(PROJECT_ROOT / "src")


class TestCLI(unittest.TestCase):

    def setUp(self):
        self.env = dict(os.environ)
        self.env["PYTHONPATH"] = f"{SRC_DIR}:{PROJECT_ROOT}:{self.env.get('PYTHONPATH', '')}"

    def test_cli_help(self):
        cmd = [sys.executable, MAIN_PY, "--help"]
        res = subprocess.run(cmd, capture_output=True, text=True, env=self.env)
        self.assertEqual(res.returncode, 0)
        self.assertIn("GraySentinel Project 02", res.stdout)
        self.assertIn("--demo", res.stdout)

    def test_cli_demo(self):
        cmd = [sys.executable, MAIN_PY, "--demo"]
        res = subprocess.run(cmd, capture_output=True, text=True, env=self.env)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Demo completed", res.stdout)

    def test_cli_validate_success(self):
        cmd = [sys.executable, MAIN_PY, "--demo"]
        subprocess.run(cmd, capture_output=True, env=self.env)

        cmd_val = [sys.executable, MAIN_PY, "--validate"]
        res = subprocess.run(cmd_val, capture_output=True, text=True, env=self.env)
        self.assertEqual(res.returncode, 0)
        self.assertIn("[PASS]", res.stdout)

    def test_cli_validate_failure(self):
        cmd = [
            sys.executable,
            MAIN_PY,
            "--findings",
            INVALID_SAMPLE,
            "--validate",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, env=self.env)
        self.assertEqual(res.returncode, 1)
        self.assertIn("[FAIL]", res.stdout)

    def test_cli_analyze_json(self):
        cmd = [sys.executable, MAIN_PY, "--demo"]
        subprocess.run(cmd, capture_output=True, env=self.env)

        cmd_an = [sys.executable, MAIN_PY, "--analyze", "--json"]
        res = subprocess.run(cmd_an, capture_output=True, text=True, env=self.env)
        self.assertEqual(res.returncode, 0)
        self.assertIn("weighted_risk_score", res.stdout)
        self.assertIn("posture_rating", res.stdout)


if __name__ == "__main__":
    unittest.main()
