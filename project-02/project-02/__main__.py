"""
GraySentinel Project 02 Entry Point for module execution.
"""

import sys
from pathlib import Path

root_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(root_dir / "src"))
sys.path.insert(0, str(root_dir))

from gray_sentinel.cli import main

if __name__ == "__main__":
    main()
