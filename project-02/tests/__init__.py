"""
GraySentinel Project 02 - Automated Test Suite
"""

import sys
from pathlib import Path

# Add project-02 and src directory to sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root / "src") not in sys.path:
    sys.path.insert(0, str(project_root / "src"))
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))
