# GraySentinel Project 02: Evidence Screenshot Capture Guide

This checklist guides the operator or auditor in capturing unedited demonstration screenshots for submission and mentor evaluation.

> **CRITICAL EVIDENCE POLICY:**
> Screenshots must be captured directly from your local terminal emulator during an interactive session. Never fabricate image files or mock graphical artifacts.

---

### Capture Sequence & Naming Scheme

Save all captured PNG images in this directory (`project-02/evidence/screenshots/`):

| File Name | Terminal View / Action | Purpose & Mentor Criteria |
| :--- | :--- | :--- |
| `01-main-menu.png` | Launch `python -m project02` or `python main.py` | Shows GraySentinel ASCII banner, session context, and numbered 9-option interactive menu. |
| `02-demo-data-loaded.png` | Select Option `[7] Demo Mode` or `[1] Load Recon` | Captures the fluid progress spinner and the green confirmation panel with scan telemetry. |
| `03-findings-table.png` | Select Option `[3] Review Findings` | Shows the structured Unicode findings table with ID, Title, Severity badges, Confidence, and Status. |
| `04-finding-details.png` | Type a finding number (e.g. `1`) in Review Findings | Shows detailed view: CVSS v3.1 vector, reproduction steps, evidence hashes, and tactical remediation. |
| `05-risk-summary.png` | Select Option `[4] Risk Summary` | Displays severity distribution bar chart, threat scoreboard, and posture diagnosis card. |
| `06-validation-results.png` | Select Option `[2] Validate Findings` | Displays the pass/warn/fail validation table with schema and reproduction depth checks. |
| `07-report-generated.png` | Select Option `[5] Generate Security Report` | Captures completion panel with timestamped archive path and Markdown report line count. |

---

### Terminal Emulator Recommendations for Clear Screenshots

- **Font:** JetBrains Mono, Fira Code, Cascadia Code, or SF Mono.
- **Terminal Width:** 90 to 110 columns (avoids line-wrapping).
- **Theme:** Dark theme (e.g., Dracula, One Dark, Solarized Dark) for optimal contrast with ANSI colors.
- **Resolution:** Full-window crop without desktop taskbars or external notifications.
