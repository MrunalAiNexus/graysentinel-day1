#!/usr/bin/env python3
"""
GraySentinel Project 02: Web Security Findings Reporter
Main CLI executable entry point.
"""

import sys
from pathlib import Path

# Add project root and src to sys.path
root_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(root_dir / "src"))
sys.path.insert(0, str(root_dir))

try:
    from gray_sentinel.cli import main
except ImportError:
    from src.gray_sentinel.cli import main

if __name__ == "__main__":
    main()

