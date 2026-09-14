"""
GraySentinel Terminal UI Engine: Polished cybersecurity console components.
Provides ANSI color formatting, banners, interactive tables, panels, spinners, and menus.
Zero external pip dependencies required - runs natively across all modern terminals.
"""

import sys
import time
import shutil
from typing import List, Dict, Any, Optional, Tuple


class Colors:
    """Standard and bright ANSI escape sequences for terminal styling."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    INVERT = "\033[7m"

    # Standard Foreground
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright Foreground
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    # Backgrounds
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_DARK = "\033[100m"


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences to accurately compute string length."""
    import re
    return re.sub(r'\033\[[0-9;]*m', '', text)


def get_terminal_width(default: int = 80) -> int:
    """Get the current terminal column width safely."""
    try:
        cols, _ = shutil.get_terminal_size((default, 24))
        return min(max(cols, 60), 120)
    except Exception:
        return default


def print_banner() -> None:
    """Render the official GraySentinel Cybersecurity Console banner."""
    width = min(get_terminal_width(), 76)
    banner_lines = [
        r"  ██████╗ ██████╗  █████╗ ██╗   ██╗███████╗███████╗███╗   ██╗████████╗",
        r" ██╔════╝ ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝",
        r" ██║  ███╗██████╔╝███████║ ╚████╔╝ ███████╗█████╗  ██╔██╗ ██║   ██║   ",
        r" ██║   ██║██╔══██╗██╔══██║  ╚██╔╝  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ",
        r" ╚██████╔╝██║  ██║██║  ██║   ██║   ███████║███████╗██║ ╚████║   ██║   ",
        r"  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ",
    ]

    print(f"\n{Colors.BRIGHT_CYAN}{Colors.BOLD}")
    for line in banner_lines:
        print(line)
    print(Colors.RESET)

    sub_title = "WEB SECURITY FINDINGS REPORTER // PROJECT 02 CONSOLE"
    decor = "═" * len(sub_title)
    print(f"  {Colors.BRIGHT_WHITE}{Colors.BOLD}{sub_title}{Colors.RESET}")
    print(f"  {Colors.DIM}{Colors.CYAN}{decor}{Colors.RESET}")
    print(f"  {Colors.DIM}Targeting Proof-First Assessment, Evidence Integrity & Threat Modeling{Colors.RESET}\n")


def print_panel(
    content: str,
    title: Optional[str] = None,
    subtitle: Optional[str] = None,
    style: str = "cyan",
    padding: int = 1,
) -> None:
    """
    Render text inside a clean Unicode double/single line box.
    Supported styles: cyan, green, red, yellow, magenta, dim.
    """
    style_map = {
        "cyan": (Colors.BRIGHT_CYAN, Colors.CYAN),
        "green": (Colors.BRIGHT_GREEN, Colors.GREEN),
        "red": (Colors.BRIGHT_RED, Colors.RED),
        "yellow": (Colors.BRIGHT_YELLOW, Colors.YELLOW),
        "magenta": (Colors.BRIGHT_MAGENTA, Colors.MAGENTA),
        "dim": (Colors.DIM, Colors.DIM),
    }
    border_color, title_color = style_map.get(style, (Colors.BRIGHT_CYAN, Colors.CYAN))

    raw_lines = content.strip().split("\n")
    max_line_len = max((len(strip_ansi(l)) for l in raw_lines), default=40)
    if title:
        max_line_len = max(max_line_len, len(strip_ansi(title)) + 4)
    if subtitle:
        max_line_len = max(max_line_len, len(strip_ansi(subtitle)) + 4)

    box_width = min(max_line_len + (padding * 2) + 2, get_terminal_width() - 2)
    inner_width = box_width - 2

    # Top border with title
    if title:
        title_stripped = strip_ansi(title)
        title_disp = f" {title} "
        remaining = inner_width - len(title_stripped) - 2
        left_pad = 2
        right_pad = max(0, remaining - left_pad)
        top = f"{border_color}╔{'═' * left_pad}{title_color}{title_disp}{border_color}{'═' * right_pad}╗{Colors.RESET}"
    else:
        top = f"{border_color}╔{'═' * inner_width}╗{Colors.RESET}"

    print(top)

    # Content lines
    for line in raw_lines:
        s_len = len(strip_ansi(line))
        pad_right = max(0, inner_width - padding - s_len)
        print(f"{border_color}║{Colors.RESET}{' ' * padding}{line}{' ' * pad_right}{border_color}║{Colors.RESET}")

    # Bottom border with optional subtitle
    if subtitle:
        sub_stripped = strip_ansi(subtitle)
        sub_disp = f" {subtitle} "
        remaining = inner_width - len(sub_stripped) - 2
        right_pad = 2
        left_pad = max(0, remaining - right_pad)
        bot = f"{border_color}╚{'═' * left_pad}{Colors.DIM}{sub_disp}{border_color}{'═' * right_pad}╝{Colors.RESET}"
    else:
        bot = f"{border_color}╚{'═' * inner_width}╝{Colors.RESET}"

    print(bot)


def render_table(
    headers: List[str],
    rows: List[List[str]],
    alignments: Optional[List[str]] = None,
    title: Optional[str] = None,
) -> None:
    """
    Render a crisp, auto-sized Unicode table.
    alignments: list of 'left', 'center', 'right'
    """
    if not headers:
        return

    num_cols = len(headers)
    if not alignments:
        alignments = ["left"] * num_cols

    # Calculate optimal column widths
    col_widths = [len(strip_ansi(h)) for h in headers]
    for row in rows:
        for i in range(min(len(row), num_cols)):
            col_widths[i] = max(col_widths[i], len(strip_ansi(str(row[i]))))

    # Pad widths
    col_widths = [w + 2 for w in col_widths]

    # Border pieces
    top_border = f"{Colors.DIM}┌" + "┬".join("─" * w for w in col_widths) + f"┐{Colors.RESET}"
    mid_border = f"{Colors.DIM}├" + "┼".join("─" * w for w in col_widths) + f"┤{Colors.RESET}"
    bot_border = f"{Colors.DIM}└" + "┴".join("─" * w for w in col_widths) + f"┘{Colors.RESET}"

    if title:
        print(f"\n{Colors.BOLD}{Colors.BRIGHT_WHITE}{title}{Colors.RESET}")

    print(top_border)

    # Render Header
    hdr_cells = []
    for i, h in enumerate(headers):
        w = col_widths[i]
        align = alignments[i] if i < len(alignments) else "left"
        h_strip = strip_ansi(h)
        diff = w - len(h_strip)
        if align == "center":
            left = diff // 2
            right = diff - left
            cell = " " * left + f"{Colors.BOLD}{Colors.BRIGHT_CYAN}{h}{Colors.RESET}" + " " * right
        elif align == "right":
            cell = " " * (diff - 1) + f"{Colors.BOLD}{Colors.BRIGHT_CYAN}{h}{Colors.RESET} "
        else:
            cell = " " + f"{Colors.BOLD}{Colors.BRIGHT_CYAN}{h}{Colors.RESET}" + " " * (diff - 1)
        hdr_cells.append(cell)

    print(f"{Colors.DIM}│{Colors.RESET}" + f"{Colors.DIM}│{Colors.RESET}".join(hdr_cells) + f"{Colors.DIM}│{Colors.RESET}")
    print(mid_border)

    # Render Rows
    if not rows:
        empty_msg = f"{Colors.DIM}No records available{Colors.RESET}"
        total_w = sum(col_widths) + len(col_widths) - 1
        pad = total_w - len(strip_ansi(empty_msg))
        print(f"{Colors.DIM}│{Colors.RESET}" + " " * (pad // 2) + empty_msg + " " * (pad - pad // 2) + f"{Colors.DIM}│{Colors.RESET}")
    else:
        for row in rows:
            row_cells = []
            for i in range(num_cols):
                val = str(row[i]) if i < len(row) else ""
                w = col_widths[i]
                align = alignments[i] if i < len(alignments) else "left"
                val_strip = strip_ansi(val)
                diff = w - len(val_strip)
                if align == "center":
                    left = diff // 2
                    right = diff - left
                    cell = " " * left + val + " " * right
                elif align == "right":
                    cell = " " * (diff - 1) + val + " "
                else:
                    cell = " " + val + " " * (diff - 1)
                row_cells.append(cell)
            print(f"{Colors.DIM}│{Colors.RESET}" + f"{Colors.DIM}│{Colors.RESET}".join(row_cells) + f"{Colors.DIM}│{Colors.RESET}")

    print(bot_border)


def severity_badge(severity: str) -> str:
    """Format severity with high-contrast color badges."""
    sev = severity.upper()
    if sev == "CRITICAL":
        return f"{Colors.BOLD}{Colors.BRIGHT_RED}CRITICAL{Colors.RESET}"
    elif sev == "HIGH":
        return f"{Colors.BOLD}{Colors.RED}HIGH{Colors.RESET}"
    elif sev == "MEDIUM":
        return f"{Colors.BOLD}{Colors.YELLOW}MEDIUM{Colors.RESET}"
    elif sev == "LOW":
        return f"{Colors.BOLD}{Colors.GREEN}LOW{Colors.RESET}"
    elif sev in ("INFO", "INFORMATIONAL"):
        return f"{Colors.BOLD}{Colors.BLUE}INFO{Colors.RESET}"
    return f"{Colors.DIM}{severity}{Colors.RESET}"


def confidence_badge(confidence: str) -> str:
    """Format confidence level with colored indicator."""
    conf = confidence.upper()
    if conf in ("CONFIRMED", "HIGH"):
        return f"{Colors.BRIGHT_GREEN}{conf}{Colors.RESET}"
    elif conf == "MEDIUM":
        return f"{Colors.BRIGHT_YELLOW}{conf}{Colors.RESET}"
    elif conf in ("LOW", "TENTATIVE"):
        return f"{Colors.BRIGHT_BLUE}{conf}{Colors.RESET}"
    return f"{Colors.DIM}{confidence}{Colors.RESET}"


def status_badge(status: str) -> str:
    """Format validation status with icons and colors."""
    st = status.upper()
    if st == "VALIDATED":
        return f"{Colors.BRIGHT_GREEN}✔ VALIDATED{Colors.RESET}"
    elif st in ("REVIEW", "UNDER_REVIEW"):
        return f"{Colors.BRIGHT_YELLOW}⚠ REVIEW{Colors.RESET}"
    elif st == "DRAFT":
        return f"{Colors.BRIGHT_BLUE}✎ DRAFT{Colors.RESET}"
    elif st == "REMEDIATED":
        return f"{Colors.BRIGHT_CYAN}✔ REMEDIATED{Colors.RESET}"
    elif st == "FALSE_POSITIVE":
        return f"{Colors.DIM}✖ FALSE POS{Colors.RESET}"
    return f"{Colors.DIM}{status}{Colors.RESET}"


def run_spinner_task(message: str, steps: List[Tuple[str, float]]) -> None:
    """
    Display a fluid spinner animation through a sequence of operational steps.
    """
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    print(f"\n{Colors.BOLD}{Colors.BRIGHT_CYAN}[*] {message}{Colors.RESET}")

    for step_text, delay in steps:
        start_t = time.time()
        i = 0
        while (time.time() - start_t) < delay:
            char = frames[i % len(frames)]
            sys.stdout.write(f"\r  {Colors.BRIGHT_YELLOW}{char}{Colors.RESET} {step_text}...")
            sys.stdout.flush()
            time.sleep(0.06)
            i += 1
        sys.stdout.write(f"\r  {Colors.BRIGHT_GREEN}✔{Colors.RESET} {step_text}\n")
        sys.stdout.flush()

    print(f"  {Colors.DIM}Done.{Colors.RESET}\n")


def print_error_box(title: str, reason: str, suggested_action: str) -> None:
    """Render a clean, user-friendly security console error box."""
    err_text = (
        f"{Colors.BOLD}{Colors.BRIGHT_RED}✗ {title}{Colors.RESET}\n\n"
        f"{Colors.BOLD}Reason:{Colors.RESET}\n"
        f"  {Colors.WHITE}{reason}{Colors.RESET}\n\n"
        f"{Colors.BOLD}Suggested Action:{Colors.RESET}\n"
        f"  {Colors.BRIGHT_CYAN}{suggested_action}{Colors.RESET}"
    )
    print_panel(err_text, title="ERROR ENCOUNTERED", style="red")


def pause_for_user(prompt: str = "Press [Enter] to return to menu...") -> None:
    """Pause interactive execution cleanly until user hits enter."""
    try:
        input(f"\n{Colors.DIM}{prompt}{Colors.RESET}")
    except (KeyboardInterrupt, EOFError):
        print()
