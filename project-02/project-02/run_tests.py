#!/usr/bin/env python3
"""
GraySentinel Project 02: Universal Test Runner.
Executes pytest if available, otherwise runs the comprehensive Python unittest discovery suite.
"""

import sys
import subprocess
from pathlib import Path

def main():
    test_dir = Path(__file__).resolve().parent / "tests"
    src_dir = Path(__file__).resolve().parent / "src"
    
    # Check if pytest is installed
    try:
        import pytest  # noqa: F401
        print("[*] Found pytest. Executing pytest suite...")
        cmd = [sys.executable, "-m", "pytest", str(test_dir), "-v"]
    except ImportError:
        print("[*] pytest not detected. Executing standard unittest discovery suite...")
        cmd = [sys.executable, "-m", "unittest", "discover", "-s", str(test_dir), "-v"]

    # Run with proper PYTHONPATH
    env = dict(sys.modules["os"].environ)
    env["PYTHONPATH"] = f"{src_dir}:{test_dir.parent}:{env.get('PYTHONPATH', '')}"
    res = subprocess.run(cmd, env=env)
    sys.exit(res.returncode)

if __name__ == "__main__":
    main()
