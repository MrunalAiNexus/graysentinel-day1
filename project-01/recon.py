#!/usr/bin/env python3
"""
recon.py
GraySentinel Cyber Defence Lab — Day 1 Project 01
Authorized Web Recon & Enumeration Tool

Candidate: Mrunal Urankar
Team: Red Team
Standard: Assigned -> Built -> Tested -> Documented -> Published -> Proven

Usage:
  python recon.py --target http://127.0.0.1:5000
  python recon.py --target http://127.0.0.1:5000 --ports 80,443,5000,8080
  python recon.py --target http://127.0.0.1:5000 --wordlist wordlists/web_paths.txt
"""

import argparse
import os
import sys

# Ensure src/ is importable
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from src.endpoints import enumerate_endpoints, load_wordlist
from src.headers import analyze_security_headers
from src.http_enum import enumerate_http_service, observe_http_methods
from src.output import write_reports
from src.port_scanner import parse_ports_argument, scan_ports
from src.robots import discover_robots_and_sitemap
from src.target import TargetValidationError, parse_and_validate_target
from src.technology import identify_technologies
from src.utils import (
    Colors,
    get_iso_timestamp,
    log_error,
    log_step,
    log_success,
    log_warning,
    print_banner,
)


def create_parser() -> argparse.ArgumentParser:
    """Configures the command-line argument parser with clear guidance."""
    parser = argparse.ArgumentParser(
        prog="recon.py",
        description=(
            "GraySentinel Cyber Defence Lab — Authorized Web Recon & Enumeration Tool.\n"
            "Performs controlled, conservative, and defensive reconnaissance against\n"
            "explicitly authorized lab targets. Built to GraySentinel Day 1 standards."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python recon.py --target http://127.0.0.1:5000\n"
            "  python recon.py --target http://192.168.56.101 --ports 22,80,443,8080\n"
            "  python recon.py --target http://127.0.0.1:5000 --wordlist wordlists/web_paths.txt\n"
            "  python recon.py --target http://127.0.0.1:5000 --no-port-scan\n"
            "\n"
            "SAFETY NOTICE:\n"
            "  Authorized Lab Use Only. Do not scan systems without prior written authorization."
        )
    )

    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target URL or IP (e.g. http://127.0.0.1:5000 or 192.168.56.101)"
    )
    parser.add_argument(
        "--ports", "-p",
        default=None,
        help="Comma-separated port list or range (default: 22,80,443,3000,3306,5000,8000,8080)"
    )
    parser.add_argument(
        "--wordlist", "-w",
        default=None,
        help="Path to custom web paths wordlist (default: built-in safe lab wordlist)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Socket and HTTP connection timeout in seconds (default: 2.0)"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.05,
        help="Delay in seconds between endpoint requests for polite rate limiting (default: 0.05)"
    )
    parser.add_argument(
        "--output", "-o",
        default="output",
        help="Output directory to store recon.json and recon.txt (default: output/)"
    )
    parser.add_argument(
        "--no-port-scan",
        action="store_true",
        help="Skip TCP port and service enumeration"
    )
    parser.add_argument(
        "--no-endpoint-enum",
        action="store_true",
        help="Skip web endpoint path enumeration"
    )
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Explicitly confirm target is an authorized training lab if outside standard private RFC ranges"
    )

    return parser


def run_reconnaissance(args: argparse.Namespace) -> int:
    """Executes the end-to-end reconnaissance workflow."""
    print_banner()

    # Step 1: Target Validation & Scope Verification
    log_step("TARGET", f"Validating target input: '{args.target}'")
    try:
        target_info = parse_and_validate_target(args.target, allow_external=args.authorized)
    except TargetValidationError as err:
        log_error(f"Target Validation Error: {err}")
        return 1
    except Exception as exc:
        log_error(f"Unexpected target error: {exc}")
        return 1

    log_success(f"Target accepted: {target_info['normalized_url']}")
    log_success(f"Hostname: {target_info['hostname']} | Resolved IP: {target_info['resolved_ip']}")
    log_success(f"Protocol: {target_info['protocol'].upper()} | Port: {target_info['port']} | Scope: {target_info['authorization_status']}")
    print()

    # Step 2: Controlled Port & Service Discovery
    network_results = {}
    if not args.no_port_scan and target_info["resolved_ip"]:
        port_list = parse_ports_argument(args.ports)
        log_step("NETWORK", f"Starting controlled port discovery on {target_info['resolved_ip']} ({len(port_list)} ports)...")
        network_results = scan_ports(target_info["resolved_ip"], port_list, timeout=args.timeout)
        print(f"  {Colors.BOLD}{'PORT':<8} | {'STATE':<10} | {'SERVICE':<28}{Colors.RESET}")
        print("  " + "-" * 50)
        for p in network_results["ports"]:
            if p["state"] == "OPEN":
                color_state = f"{Colors.GREEN}{p['state']:<10}{Colors.RESET}"
            elif p["state"] == "CLOSED":
                color_state = f"{Colors.DIM}{p['state']:<10}{Colors.RESET}"
            else:
                color_state = f"{Colors.YELLOW}{p['state']:<10}{Colors.RESET}"
            print(f"  {p['port']:<8} | {color_state} | {p['service']}")
        log_success(f"Port scan completed. Open ports found: {network_results['open_ports_count']}")
    else:
        log_step("NETWORK", "Port scan skipped per configuration.")
    print()

    # Step 3: HTTP / HTTPS Service Enumeration
    log_step("HTTP", f"Connecting to web service: {target_info['normalized_url']}...")
    http_data = enumerate_http_service(target_info["normalized_url"], timeout=args.timeout)

    if http_data.get("error") and http_data.get("status_code") is None:
        log_error(f"Failed to connect to HTTP service: {http_data['error']}")
        log_warning("Target service may be offline or unreachable on this port.")
    else:
        log_success(f"HTTP Response: {http_data.get('status_code')} {http_data.get('status_message')} ({http_data.get('response_time_ms')} ms)")
        if http_data.get("server_header") and http_data.get("server_header") != "Not exposed in headers":
            log_success(f"Server Header Exposed: {http_data.get('server_header')}")
        if http_data.get("html_title"):
            log_success(f"HTML Title: \"{http_data.get('html_title')}\"")
        if http_data.get("redirect_count", 0) > 0:
            log_warning(f"Redirects Observed: {http_data['redirect_count']} (Final URL: {http_data['final_url']})")
    print()

    # Step 4: HTTP Methods Observation (Safe OPTIONS request)
    methods_data = {}
    if http_data.get("status_code"):
        log_step("METHODS", "Observing supported HTTP methods via safe OPTIONS probe...")
        methods_data = observe_http_methods(target_info["normalized_url"], timeout=args.timeout)
        if methods_data.get("allowed_methods"):
            log_success(f"Allowed Methods Observed: {', '.join(methods_data['allowed_methods'])}")
        else:
            log_warning(methods_data.get("observation", "No explicit Allow header returned."))
    print()

    # Step 5: Security Header Analysis (Strictly as Observations)
    log_step("SECURITY HEADERS", "Analyzing HTTP defense-in-depth headers...")
    headers_analysis = analyze_security_headers(
        http_data.get("headers", {}),
        is_https=target_info["protocol"] == "https"
    )
    for h in headers_analysis["details"]:
        if h["status"] == "PRESENT":
            print(f"  {Colors.GREEN}[+] {h['header']}: PRESENT{Colors.RESET} -> {Colors.DIM}{h['observation']}{Colors.RESET}")
        else:
            print(f"  {Colors.YELLOW}[-] {h['header']}: MISSING{Colors.RESET} (Observation: {h['why_it_matters'][:60]}...)")
    print()

    # Step 6: Passive Technology Identification
    log_step("TECHNOLOGY", "Passively identifying application technologies & framework markers...")
    tech_findings = identify_technologies(http_data.get("headers", {}), http_data.get("body_sample", ""))
    if tech_findings:
        for t in tech_findings:
            print(f"  {Colors.CYAN}[*]{Colors.RESET} Technology : {Colors.BOLD}{t['name']}{Colors.RESET} ({t['category']})")
            print(f"      Confidence : {t['confidence']}")
            print(f"      Evidence   : {t['evidence']}")
    else:
        print("  [*] No specific application framework markers detected.")
    print()

    # Step 7: Robots.txt & Sitemap Discovery
    log_step("ROBOTS/SITEMAP", "Checking for /robots.txt and /sitemap.xml...")
    robots_data = discover_robots_and_sitemap(target_info["base_url"], timeout=args.timeout)
    if robots_data["robots"]["present"]:
        log_success(f"/robots.txt found (HTTP 200). Disallowed paths: {len(robots_data['robots']['parsed'].get('disallowed_paths', []))}")
        for path in robots_data["robots"]["parsed"].get("disallowed_paths", []):
            print(f"    └── Disallow: {path}")
    else:
        log_warning(f"/robots.txt: Not present (Status: {robots_data['robots']['status_code'] or 'Unreachable'})")

    if robots_data["sitemap"]["present"]:
        log_success(f"/sitemap.xml found (HTTP 200). URLs indexed: {robots_data['sitemap']['url_count']}")
    else:
        log_warning(f"/sitemap.xml: Not present (Status: {robots_data['sitemap']['status_code'] or 'Unreachable'})")
    print()

    # Step 8: Controlled Web Endpoint Enumeration
    endpoints_data = {}
    if not args.no_endpoint_enum:
        try:
            wordlist = load_wordlist(args.wordlist)
        except Exception as err:
            log_error(f"Error loading wordlist: {err}")
            return 1

        log_step("ENDPOINTS", f"Executing controlled endpoint enumeration ({len(wordlist)} paths, delay: {args.delay}s)...")
        print(f"  {Colors.BOLD}{'STATUS':<8} | {'LENGTH':<10} | {'CATEGORY':<28} | {'PATH'}{Colors.RESET}")
        print("  " + "-" * 66)

        def print_endpoint_row(ep: dict):
            status = ep.get("status_code")
            if status == 200:
                sc_disp = f"{Colors.GREEN}{status:<8}{Colors.RESET}"
            elif status in (301, 302, 307, 308):
                sc_disp = f"{Colors.CYAN}{status:<8}{Colors.RESET}"
            elif status in (401, 403):
                sc_disp = f"{Colors.YELLOW}{status:<8}{Colors.RESET}"
            elif status == 404:
                sc_disp = f"{Colors.DIM}404     {Colors.RESET}"
            else:
                sc_disp = f"{Colors.RED}{str(status) if status else 'ERR':<8}{Colors.RESET}"

            length_str = f"{ep.get('content_length')} B" if ep.get("content_length") is not None else "-"
            print(f"  {sc_disp} | {length_str:<10} | {ep.get('category')[:28]:<28} | {ep.get('path')}")

        endpoints_data = enumerate_endpoints(
            target_info["base_url"],
            wordlist,
            delay=args.delay,
            timeout=args.timeout,
            progress_callback=print_endpoint_row
        )
        log_success(f"Endpoint enumeration complete. Paths with response: {endpoints_data['discovered_count']}")
    else:
        log_step("ENDPOINTS", "Endpoint enumeration skipped per configuration.")
    print()

    # Step 9: Structured Output Generation
    timestamp = get_iso_timestamp()
    report_bundle = {
        "metadata": {
            "tool": "GraySentinel Web Recon & Enumeration Tool",
            "version": "1.0.0",
            "candidate": "Mrunal Urankar",
            "team": "Red Team",
            "project": "Project 01 — Authorized Web Recon & Enumeration",
            "standard": "Assigned -> Built -> Tested -> Documented -> Published -> Proven"
        },
        "target": target_info,
        "network": network_results,
        "web": {
            "status_code": http_data.get("status_code"),
            "status_message": http_data.get("status_message"),
            "response_time_ms": http_data.get("response_time_ms"),
            "content_type": http_data.get("content_type"),
            "content_length": http_data.get("content_length"),
            "server_header": http_data.get("server_header"),
            "html_title": http_data.get("html_title"),
            "final_url": http_data.get("final_url"),
            "redirect_count": http_data.get("redirect_count", 0),
            "redirects": http_data.get("redirects", []),
            "headers": http_data.get("headers", {})
        },
        "http_methods": methods_data,
        "headers": headers_analysis,
        "technologies": tech_findings,
        "robots": robots_data.get("robots", {}),
        "sitemap": robots_data.get("sitemap", {}),
        "endpoints": endpoints_data,
        "timestamp": timestamp
    }

    log_step("OUTPUT", f"Generating structured reports in '{args.output}/'...")
    try:
        written = write_reports(report_bundle, output_dir=args.output)
        log_success(f"Machine-readable JSON saved : {written['json_path']}")
        log_success(f"Human-readable Text saved   : {written['text_path']}")
    except Exception as exc:
        log_error(f"Failed to write report files: {exc}")
        return 1

    print()
    log_success(f"{Colors.BOLD}Reconnaissance mission complete. All evidence recorded.{Colors.RESET}")
    return 0


def main() -> None:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    exit_code = run_reconnaissance(args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
