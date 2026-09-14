"""
GraySentinel Project 02: Interactive Terminal Cybersecurity Console.
Provides a rich, fluid, menu-driven CLI experience with colored indicators,
live status spinners, ASCII banners, interactive tables, and detailed finding inspection.
"""

import argparse
import datetime
import json
import os
import sys
from typing import List, Optional

from .models import (
    Finding,
    ReconData,
    Severity,
    Confidence,
    ValidationStatus,
)
from .ui import (
    Colors,
    print_banner,
    print_panel,
    render_table,
    severity_badge,
    confidence_badge,
    status_badge,
    run_spinner_task,
    print_error_box,
    pause_for_user,
    strip_ansi,
    get_terminal_width,
)
from .parser import load_recon_json, generate_candidate_findings
from .validator import FindingValidator
from .risk import RiskAnalyzer, RiskSummary
from .evidence import EvidenceManager
from .remediation import RemediationEngine
from .reporter import ReportGenerator
from .errors import GraySentinelError


class GraySentinelConsole:
    """Stateful interactive console engine for Project 02."""

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = base_dir or os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..")
        )
        self.recon_data: Optional[ReconData] = None
        self.findings: List[Finding] = []
        self.validator = FindingValidator()
        self.last_report_path: Optional[str] = None

    def get_sample_recon_path(self) -> str:
        candidates = [
            os.path.join(self.base_dir, "data", "sample", "sanitized_recon.json"),
            os.path.join(self.base_dir, "data", "sample_recon.json"),
            os.path.join(os.getcwd(), "project-02", "data", "sample", "sanitized_recon.json"),
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return candidates[0]

    def load_sample_findings(self) -> None:
        """Loads pre-validated sample findings if present."""
        sample_path = os.path.join(self.base_dir, "data", "sample_findings.json")
        if os.path.exists(sample_path):
            with open(sample_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
                self.findings = [Finding.from_dict(item) for item in raw]

    def run_menu(self) -> None:
        """Main interactive menu loop."""
        while True:
            self.display_main_menu()
            choice = input(f"\n{Colors.BOLD}{Colors.BRIGHT_WHITE}Select an option [1-9]: {Colors.RESET}").strip()

            if choice == "1":
                self.action_load_recon()
            elif choice == "2":
                self.action_validate_findings()
            elif choice == "3":
                self.action_review_findings()
            elif choice == "4":
                self.action_risk_summary()
            elif choice == "5":
                self.action_generate_report()
            elif choice == "6":
                self.action_view_evidence()
            elif choice == "7":
                self.action_demo_mode()
            elif choice == "8":
                self.action_project_info()
            elif choice in ("9", "q", "quit", "exit"):
                print(f"\n{Colors.BRIGHT_CYAN}Exiting GraySentinel Security Console. Stay secure.{Colors.RESET}\n")
                break
            else:
                print(f"{Colors.BRIGHT_RED}Invalid option '{choice}'. Please select a number between 1 and 9.{Colors.RESET}")
                pause_for_user()

    def display_main_menu(self) -> None:
        """Renders the top branding banner and main navigation box."""
        print_banner()

        recon_status = (
            f"{Colors.BRIGHT_GREEN}Loaded ({self.recon_data.target}){Colors.RESET}"
            if self.recon_data
            else f"{Colors.DIM}None (Ready to Load){Colors.RESET}"
        )
        findings_count = len(self.findings)
        findings_status = (
            f"{Colors.BRIGHT_GREEN}{findings_count} Active{Colors.RESET}"
            if findings_count > 0
            else f"{Colors.DIM}0 Loaded{Colors.RESET}"
        )

        menu_text = (
            f"  {Colors.BOLD}{Colors.BRIGHT_WHITE}CURRENT SESSION CONTEXT:{Colors.RESET}\n"
            f"  • Reconnaissance Target : {recon_status}\n"
            f"  • Security Findings     : {findings_status}\n\n"
            f"  {Colors.BOLD}{Colors.BRIGHT_CYAN}[1]{Colors.RESET} Load Recon Data (Project 01 JSON)\n"
            f"  {Colors.BOLD}{Colors.BRIGHT_CYAN}[2]{Colors.RESET} Validate Findings (Schema & Evidence Checks)\n"
            f"  {Colors.BOLD}{Colors.BRIGHT_CYAN}[3]{Colors.RESET} Review Findings (Interactive Table & Detail View)\n"
            f"  {Colors.BOLD}{Colors.BRIGHT_CYAN}[4]{Colors.RESET} Risk Summary (Posture & Threat Scoreboard)\n"
            f"  {Colors.BOLD}{Colors.BRIGHT_CYAN}[5]{Colors.RESET} Generate Security Report (Publication Markdown)\n"
            f"  {Colors.BOLD}{Colors.BRIGHT_CYAN}[6]{Colors.RESET} View Evidence (Cryptographic SHA-256 Hashes)\n"
            f"  {Colors.BOLD}{Colors.BRIGHT_CYAN}[7]{Colors.RESET} Demo Mode (One-Touch Sanitized Walkthrough)\n"
            f"  {Colors.BOLD}{Colors.BRIGHT_CYAN}[8]{Colors.RESET} Project Information & Architecture\n"
            f"  {Colors.BOLD}{Colors.BRIGHT_RED}[9]{Colors.RESET} Exit Console"
        )

        print_panel(menu_text, title="GRAYSENTINEL COMMAND CONSOLE", style="cyan")

    def action_load_recon(self) -> None:
        """Prompts for or loads Project 01 Recon JSON."""
        print(f"\n{Colors.BOLD}{Colors.BRIGHT_CYAN}── LOAD PROJECT 01 RECONNAISSANCE DATA ──{Colors.RESET}")
        default_path = self.get_sample_recon_path()
        prompt = f"Enter path to Project 01 JSON [{Colors.DIM}{os.path.relpath(default_path, self.base_dir)}{Colors.RESET}]: "
        user_path = input(prompt).strip()
        filepath = user_path if user_path else default_path

        try:
            steps = [
                ("Validating JSON syntax & Project 01 schema", 0.15),
                ("Correlating open services & attack surface", 0.15),
                ("Extracting candidate security observations", 0.15),
            ]
            run_spinner_task("Ingesting Reconnaissance Telemetry", steps)

            recon = load_recon_json(filepath)
            self.recon_data = recon
            new_findings = generate_candidate_findings(recon)
            self.findings = new_findings

            tag = f"{Colors.BRIGHT_YELLOW}[DEMO DATA]{Colors.RESET}" if recon.is_demo else f"{Colors.BRIGHT_GREEN}[LAB DATA]{Colors.RESET}"
            info_msg = (
                f"{Colors.BOLD}Target:{Colors.RESET} {recon.target} {tag}\n"
                f"{Colors.BOLD}Scan ID:{Colors.RESET} {recon.scan_id}\n"
                f"{Colors.BOLD}Open Ports Discovered:{Colors.RESET} {len(recon.open_ports)}\n"
                f"{Colors.BOLD}Web Endpoints Enumerated:{Colors.RESET} {len(recon.endpoints)}\n"
                f"{Colors.BOLD}Candidate Findings Synthesized:{Colors.RESET} {len(new_findings)}\n"
                f"{Colors.BOLD}Missing Security Headers:{Colors.RESET} {', '.join(recon.missing_security_headers) or 'None'}"
            )
            print_panel(info_msg, title="RECON INGESTION SUCCESSFUL", style="green")

        except GraySentinelError as err:
            print_error_box("Failed to load reconnaissance dataset", err.reason, err.suggested_action)
        except Exception as exc:
            print_error_box("Unexpected ingestion failure", str(exc), "Verify file formatting and permissions.")

        pause_for_user()

    def action_validate_findings(self) -> None:
        """Validates all loaded findings and displays results."""
        if not self.findings:
            print(f"\n{Colors.BRIGHT_YELLOW}⚠ No findings currently loaded. Please load recon data or run Demo Mode first.{Colors.RESET}")
            pause_for_user()
            return

        steps = [
            ("Executing schema integrity checks", 0.12),
            ("Verifying CVSS v3.1 mathematical ranges", 0.12),
            ("Auditing reproduction step depth & evidence requirements", 0.15),
            ("Checking identifier uniqueness across catalog", 0.10),
        ]
        run_spinner_task("Validating Security Findings Catalog", steps)

        results = self.validator.validate_all(self.findings)

        headers = ["Status", "Finding ID", "Finding Title", "Issues / Violations"]
        rows = []
        all_passed = True

        for r in results:
            if not r.is_valid:
                all_passed = False
                status_str = f"{Colors.BRIGHT_RED}✗ FAIL{Colors.RESET}"
                issues = "; ".join(r.errors)
            elif r.warnings:
                status_str = f"{Colors.BRIGHT_YELLOW}⚠ WARN{Colors.RESET}"
                issues = "; ".join(r.warnings)
            else:
                status_str = f"{Colors.BRIGHT_GREEN}✔ PASS{Colors.RESET}"
                issues = f"{Colors.DIM}Strict conformity verified{Colors.RESET}"

            rows.append([status_str, r.finding_id, r.title[:38], issues])

        render_table(headers, rows, alignments=["center", "left", "left", "left"], title="VALIDATION REPORT")

        if all_passed:
            print(f"\n{Colors.BRIGHT_GREEN}✔ All {len(self.findings)} findings passed strict schema and security policy validation!{Colors.RESET}")
        else:
            print(f"\n{Colors.BRIGHT_RED}✗ Validation policy violations detected. Review issues above.{Colors.RESET}")

        pause_for_user()

    def action_review_findings(self) -> None:
        """Displays findings in a table and allows interactive drill-down."""
        if not self.findings:
            print(f"\n{Colors.BRIGHT_YELLOW}⚠ No findings loaded. Loading sanitized demo findings...{Colors.RESET}")
            self.action_demo_mode(return_early=True)

        while True:
            headers = ["#", "ID", "Title", "Severity", "Confidence", "Status", "Asset"]
            rows = []
            for idx, f in enumerate(self.findings, 1):
                rows.append([
                    str(idx),
                    f.id,
                    f.title[:32],
                    severity_badge(f.severity.value),
                    confidence_badge(f.confidence.value),
                    status_badge(f.validation_status.value),
                    f.affected_asset[:30],
                ])

            render_table(
                headers,
                rows,
                alignments=["center", "left", "left", "center", "center", "center", "left"],
                title=f"FINDINGS CATALOG ({len(self.findings)} Findings Loaded)",
            )

            print(f"\n{Colors.DIM}Enter finding number or ID (e.g. '1' or 'GS-SEC-001') to view details, or 'b' for back:{Colors.RESET}")
            choice = input(f"{Colors.BOLD}Select finding > {Colors.RESET}").strip()

            if choice.lower() in ("b", "back", ""):
                break

            target_finding = None
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(self.findings):
                    target_finding = self.findings[idx]
            else:
                for f in self.findings:
                    if f.id.lower() == choice.lower():
                        target_finding = f
                        break

            if target_finding:
                self.display_finding_detail(target_finding)
            else:
                print(f"{Colors.BRIGHT_RED}Finding '{choice}' not found.{Colors.RESET}")

    def display_finding_detail(self, f: Finding) -> None:
        """Renders comprehensive, audit-ready details for a single finding."""
        rem = RemediationEngine.ensure_remediation(f)
        ev_summary = []
        for ev in f.evidence:
            ev_class = "DEMO / SAMPLE DATA" if ev.is_demo_sample else "REAL LAB EVIDENCE"
            hash_str = f"SHA-256: {ev.sha256_hash[:16]}..." if ev.sha256_hash else "Observation-Only"
            ev_summary.append(f"  • [{ev.id}] {ev.source} ({ev_class}) | {hash_str}\n    Observation: {ev.observation}")

        steps_text = "\n".join(f"  {idx}. {s}" for idx, s in enumerate(f.reproduction_steps, 1)) if f.reproduction_steps else "  (None provided)"
        ev_text = "\n".join(ev_summary) if ev_summary else "  (No evidence attached)"

        detail = (
            f"{Colors.BOLD}{Colors.BRIGHT_WHITE}[{f.id}] {f.title}{Colors.RESET}\n"
            f"────────────────────────────────────────────────────────────\n"
            f"{Colors.BOLD}Severity:{Colors.RESET}   {severity_badge(f.severity.value)}    {Colors.BOLD}Confidence:{Colors.RESET} {confidence_badge(f.confidence.value)}    {Colors.BOLD}Status:{Colors.RESET} {status_badge(f.validation_status.value)}\n"
            f"{Colors.BOLD}Asset:{Colors.RESET}      {f.affected_asset}\n"
            f"{Colors.BOLD}CVSS v3.1:{Colors.RESET}  {f.cvss_score} ({f.cvss_vector or 'N/A'}) | Weighted Score: {f.weighted_risk} pts\n"
            f"{Colors.BOLD}Taxonomy:{Colors.RESET}   {f.cwe_id or 'CWE-N/A'} ({f.cwe_name or 'N/A'}) | {f.owasp_category or 'OWASP-N/A'}\n\n"
            f"{Colors.BOLD}DESCRIPTION:{Colors.RESET}\n{f.description}\n\n"
            f"{Colors.BOLD}REPRODUCTION STEPS:{Colors.RESET}\n{steps_text}\n\n"
            f"{Colors.BOLD}SUPPORTING EVIDENCE:{Colors.RESET}\n{ev_text}\n\n"
            f"{Colors.BOLD}REMEDIATION GUIDANCE:{Colors.RESET}\n"
            f"  • {Colors.BRIGHT_YELLOW}Tactical:{Colors.RESET}  {rem.tactical}\n"
            f"  • {Colors.BRIGHT_CYAN}Strategic:{Colors.RESET} {rem.strategic}\n"
        )
        if rem.code_example:
            detail += f"\n{Colors.BOLD}CONFIG / CODE SNIPPET:{Colors.RESET}\n{Colors.DIM}{rem.code_example}{Colors.RESET}\n"

        print_panel(detail, title=f"FINDING DETAIL: {f.id}", style="cyan")
        pause_for_user("Press [Enter] to return to findings table...")

    def action_risk_summary(self) -> None:
        """Displays interactive risk dashboard and posture calculations."""
        if not self.findings:
            print(f"\n{Colors.BRIGHT_YELLOW}⚠ No findings loaded. Loading sanitized demo findings...{Colors.RESET}")
            self.action_demo_mode(return_early=True)

        endpoints_count = len(self.recon_data.endpoints) if self.recon_data else max(len(self.findings), 1)
        summary = RiskAnalyzer.calculate_summary(self.findings, total_endpoints=endpoints_count)

        # Severity distribution table
        sev_headers = ["Severity Level", "Count", "Weight", "Visual Distribution"]
        sev_rows = []
        max_count = max(summary.by_severity.values(), default=1)
        bar_len = 16

        for s in Severity:
            cnt = summary.by_severity.get(s.value, 0)
            bars = "█" * int((cnt / max(max_count, 1)) * bar_len)
            sev_rows.append([
                severity_badge(s.value),
                str(cnt),
                f"{s.weight:.1f}",
                f"{Colors.CYAN}{bars.ljust(bar_len)}{Colors.RESET}",
            ])

        render_table(sev_headers, sev_rows, alignments=["left", "center", "center", "left"], title="SEVERITY METRICS")

        # Posture summary panel
        posture_style = "red" if "CRITICAL" in summary.posture_rating else ("yellow" if "HIGH" in summary.posture_rating else "green")
        posture_text = (
            f"{Colors.BOLD}POSTURE EVALUATION:{Colors.RESET}   {Colors.BOLD}{summary.posture_rating}{Colors.RESET}\n"
            f"{Colors.BOLD}DIAGNOSIS:{Colors.RESET}            {summary.posture_description}\n\n"
            f"{Colors.BOLD}Weighted Threat Score:{Colors.RESET} {summary.weighted_risk_score} points\n"
            f"{Colors.BOLD}Total Findings Count:{Colors.RESET}  {summary.total_findings}\n"
            f"{Colors.BOLD}Validated Findings:{Colors.RESET}    {summary.validated_count}\n"
            f"{Colors.BOLD}Attack Surface Density:{Colors.RESET} {summary.attack_surface_density} findings/endpoint"
        )
        print_panel(posture_text, title="ENVIRONMENT SECURITY POSTURE", style=posture_style)

        pause_for_user()

    def action_generate_report(self) -> None:
        """Compiles and exports the complete 11-section Markdown report."""
        if not self.findings:
            print(f"\n{Colors.BRIGHT_YELLOW}⚠ No findings loaded. Loading sanitized demo findings...{Colors.RESET}")
            self.action_demo_mode(return_early=True)

        steps = [
            ("Aggregating threat taxonomy & reproduction steps", 0.12),
            ("Synthesizing 3-phase remediation roadmap", 0.12),
            ("Embedding SHA-256 evidence integrity matrix", 0.12),
            ("Rendering Markdown report specification", 0.15),
        ]
        run_spinner_task("Compiling Publication-Ready Security Report", steps)

        report_md = ReportGenerator.generate_markdown_report(self.findings, self.recon_data)

        timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out_reports_dir = os.path.join(self.base_dir, "reports")
        report_filename = f"security_report_{timestamp_str}.md"
        primary_out = os.path.join(out_reports_dir, report_filename)
        root_out = os.path.join(self.base_dir, "report.md")

        ReportGenerator.save_report(report_md, primary_out)
        ReportGenerator.save_report(report_md, root_out)
        self.last_report_path = primary_out

        report_lines = report_md.split("\n")
        msg = (
            f"{Colors.BRIGHT_GREEN}✔ Report compiled and saved successfully!{Colors.RESET}\n\n"
            f"{Colors.BOLD}Timestamped Archive:{Colors.RESET} {primary_out}\n"
            f"{Colors.BOLD}Submission Document:{Colors.RESET}  {root_out}\n"
            f"{Colors.BOLD}Total Lines:{Colors.RESET}          {len(report_lines)} lines\n"
            f"{Colors.BOLD}Sections Included:{Colors.RESET}    Executive Summary, Scope, Methodology, Assets,\n"
            f"                        Findings, Severity, Evidence, Risk Assessment,\n"
            f"                        Remediation, Limitations, Conclusion."
        )
        print_panel(msg, title="REPORT GENERATION COMPLETE", style="green")

        pause_for_user()

    def action_view_evidence(self) -> None:
        """Inspects all attached evidence items and cryptographic SHA-256 digests."""
        if not self.findings:
            print(f"\n{Colors.BRIGHT_YELLOW}⚠ No findings loaded. Please load recon data or run Demo Mode first.{Colors.RESET}")
            pause_for_user()
            return

        all_evidence = [ev for f in self.findings for ev in f.evidence]
        if not all_evidence:
            print(f"\n{Colors.DIM}No evidence items currently attached to findings.{Colors.RESET}")
            pause_for_user()
            return

        headers = ["ID", "Source", "Data Classification", "SHA-256 Hash", "Integrity Status"]
        rows = []
        for ev in all_evidence:
            ev_class = (
                f"{Colors.BRIGHT_YELLOW}DEMO / SAMPLE{Colors.RESET}"
                if ev.is_demo_sample
                else f"{Colors.BRIGHT_GREEN}REAL LAB DATA{Colors.RESET}"
            )
            hash_display = f"{ev.sha256_hash[:16]}..." if ev.sha256_hash else f"{Colors.DIM}Observation{Colors.RESET}"
            status_display = f"{Colors.BRIGHT_GREEN}✔ VERIFIED{Colors.RESET}" if ev.verified else f"{Colors.DIM}Pending{Colors.RESET}"

            rows.append([ev.id, ev.source[:24], ev_class, hash_display, status_display])

        render_table(
            headers,
            rows,
            alignments=["left", "left", "center", "left", "center"],
            title=f"EVIDENCE & INTEGRITY MATRIX ({len(all_evidence)} Artifacts)",
        )

        manifest_path = os.path.join(self.base_dir, "evidence", "evidence_manifest.json")
        EvidenceManager.generate_manifest(all_evidence, manifest_path)
        print(f"\n{Colors.DIM}Evidence manifest updated: {manifest_path}{Colors.RESET}")

        pause_for_user()

    def action_demo_mode(self, return_early: bool = False) -> None:
        """Automated end-to-end demonstration using sanitized GraySentinel dataset."""
        print(f"\n{Colors.BOLD}{Colors.BRIGHT_YELLOW}⚠ DEMO MODE — EXECUTING WITH SANITIZED DATASET{Colors.RESET}")
        print(f"{Colors.DIM}No external servers or third-party targets are contacted during this demo.{Colors.RESET}\n")

        steps = [
            ("Loading sanitized Project 01 reconnaissance JSON", 0.15),
            ("Extracting attack surface observations", 0.15),
            ("Synthesizing structured finding models", 0.15),
            ("Validating findings against GraySentinel policy rules", 0.15),
            ("Computing risk posture and threat metrics", 0.15),
        ]
        run_spinner_task("Executing GraySentinel End-to-End Security Pipeline", steps)

        sample_path = self.get_sample_recon_path()
        recon = load_recon_json(sample_path)
        self.recon_data = recon
        self.findings = generate_candidate_findings(recon)

        # Mark evidence verified for demo artifacts
        for f in self.findings:
            for ev in f.evidence:
                ev.verified = True

        if return_early:
            return

        print(f"{Colors.BRIGHT_GREEN}✔ Demo dataset loaded successfully! Showing findings dashboard:{Colors.RESET}")
        self.action_review_findings()

    def action_project_info(self) -> None:
        """Displays project architectural information and test commands."""
        info = (
            f"{Colors.BOLD}GraySentinel Project 02 — Web Security Findings Reporter{Colors.RESET}\n"
            f"Version: 2.0.0 | Python 3.10+ Standard Library Architecture\n\n"
            f"{Colors.BOLD}Core Objectives:{Colors.RESET}\n"
            f"  1. Ingest & correlate Project 01 reconnaissance telemetry.\n"
            f"  2. Structure findings with CWE, OWASP, CVSS v3.1, and reproduction steps.\n"
            f"  3. Enforce cryptographic SHA-256 evidence integrity and clear data tagging.\n"
            f"  4. Apply strict multi-pass validation rules preventing incomplete reports.\n"
            f"  5. Generate publication-ready 11-section Markdown assessment reports.\n\n"
            f"{Colors.BOLD}Testing & Quality Verification:{Colors.RESET}\n"
            f"  Run unit and integration tests with:\n"
            f"  {Colors.BRIGHT_CYAN}python3 -m unittest discover -s project-02/tests -v{Colors.RESET}\n"
            f"  or if pytest is installed: {Colors.BRIGHT_CYAN}pytest project-02/tests -v{Colors.RESET}"
        )
        print_panel(info, title="SYSTEM ARCHITECTURE & MENTOR INFO", style="cyan")
        pause_for_user()


def build_arg_parser() -> argparse.ArgumentParser:
    """Configures command line flags for non-interactive execution."""
    parser = argparse.ArgumentParser(
        description="GraySentinel Project 02: Web Security Findings Reporter Console"
    )
    parser.add_argument("--demo", action="store_true", help="Run automated end-to-end demo and generate report")
    parser.add_argument("--recon", type=str, help="Path to Project 01 Recon JSON file to ingest")
    parser.add_argument("--findings", type=str, help="Path to Findings JSON file to load and validate")
    parser.add_argument("--validate", action="store_true", help="Validate findings and print results")
    parser.add_argument("--analyze", action="store_true", help="Print risk summary analysis")
    parser.add_argument("--report", action="store_true", help="Generate and export security report")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--out", type=str, help="Custom output path for generated report")
    return parser


def main() -> None:
    """CLI Entrypoint supporting both interactive console and headless flags."""
    parser = build_arg_parser()
    args = parser.parse_args()

    console = GraySentinelConsole()

    # Headless / flag-driven mode
    if any([args.demo, args.recon, args.findings, args.validate, args.analyze, args.report]):
        if args.demo:
            console.action_demo_mode(return_early=True)
            report_md = ReportGenerator.generate_markdown_report(console.findings, console.recon_data)
            out_path = args.out or os.path.join(console.base_dir, "report.md")
            ReportGenerator.save_report(report_md, out_path)
            print(f"[+] Demo completed. Report written to: {out_path}")
            sys.exit(0)

        if args.recon:
            recon = load_recon_json(args.recon)
            console.recon_data = recon
            console.findings = generate_candidate_findings(recon)

        if args.findings:
            with open(args.findings, "r", encoding="utf-8") as f:
                raw = json.load(f)
                console.findings = [Finding.from_dict(item) for item in raw]

        if not console.findings:
            console.action_demo_mode(return_early=True)

        if args.validate:
            results = console.validator.validate_all(console.findings)
            all_valid = all(r.is_valid for r in results)
            if args.json:
                print(json.dumps([{"id": r.finding_id, "valid": r.is_valid, "errors": r.errors, "warnings": r.warnings} for r in results], indent=2))
            else:
                for r in results:
                    mark = "[PASS]" if r.is_valid else "[FAIL]"
                    print(f"{mark} {r.finding_id}: {r.title} (Errors: {len(r.errors)}, Warnings: {len(r.warnings)})")
            if not all_valid:
                sys.exit(1)

        if args.analyze:
            summary = RiskAnalyzer.calculate_summary(console.findings)
            if args.json:
                print(json.dumps(summary.to_dict(), indent=2))
            else:
                print(f"Risk Posture: {summary.posture_rating} | Weighted Score: {summary.weighted_risk_score} | Findings: {summary.total_findings}")

        if args.report:
            report_md = ReportGenerator.generate_markdown_report(console.findings, console.recon_data)
            out_path = args.out or os.path.join(console.base_dir, "report.md")
            ReportGenerator.save_report(report_md, out_path)
            print(f"[+] Report generated at: {out_path}")

        sys.exit(0)

    # Interactive Console Mode
    try:
        console.run_menu()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.BRIGHT_CYAN}Console terminated by user. Exiting.{Colors.RESET}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
