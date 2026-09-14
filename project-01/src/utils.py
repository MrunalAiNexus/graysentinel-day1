"""
src/utils.py
Common helper utilities: ANSI terminal styling, timestamp formatting,
and structured terminal output helpers.
"""

import datetime
import os
import sys
from typing import Any, Dict


class Colors:
    """ANSI color escape codes with automatic TTY and NO_COLOR check."""
    ENABLED = (
        sys.stdout.isatty()
        and "NO_COLOR" not in os.environ
        and os.environ.get("TERM") != "dumb"
    )

    CYAN = "\033[96m" if ENABLED else ""
    BLUE = "\033[94m" if ENABLED else ""
    GREEN = "\033[92m" if ENABLED else ""
    YELLOW = "\033[93m" if ENABLED else ""
    RED = "\033[91m" if ENABLED else ""
    BOLD = "\033[1m" if ENABLED else ""
    DIM = "\033[2m" if ENABLED else ""
    RESET = "\033[0m" if ENABLED else ""


def get_iso_timestamp() -> str:
    """Returns the current UTC timestamp formatted as ISO 8601."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def print_banner() -> None:
    """Displays the GraySentinel authorized reconnaissance banner."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}======================================================================
  GRAYSENTINEL CYBER DEFENCE LAB — DAY 1 PROJECT 01
  AUTHORIZED WEB RECON & ENUMERATION TOOL
  Candidate: Mrunal Urankar | Team: Red Team
======================================================================{Colors.RESET}
{Colors.YELLOW}{Colors.BOLD}[!] NOTICE: AUTHORIZED LAB USE ONLY{Colors.RESET}
{Colors.DIM}This tool is strictly restricted to controlled lab targets and explicit
training environments. Unauthorized network scanning is strictly prohibited.{Colors.RESET}
----------------------------------------------------------------------"""
    print(banner)


def log_step(category: str, message: str) -> None:
    """Standardized informational progress message."""
    print(f"{Colors.BLUE}[*]{Colors.RESET} {Colors.BOLD}[{category}]{Colors.RESET} {message}")


def log_success(message: str) -> None:
    """Standardized success message."""
    print(f"{Colors.GREEN}[+]{Colors.RESET} {message}")


def log_warning(message: str) -> None:
    """Standardized observation / warning message."""
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {message}")


def log_error(message: str) -> None:
    """Standardized error message."""
    print(f"{Colors.RED}[-]{Colors.RESET} {message}")
