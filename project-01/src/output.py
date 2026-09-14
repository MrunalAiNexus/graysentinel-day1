"""
src/output.py
Generates machine-readable JSON (recon.json) and human-readable text report (recon.txt).
Strictly adheres to GraySentinel Cyber Defence Lab reporting guidelines.
"""

import json
import os
from typing import Any, Dict


def build_json_report(data: Dict[str, Any]) -> str:
    """Serializes the full reconnaissance dataset into clean, formatted JSON."""
    return json.dumps(data, indent=2)


def build_text_report(data: Dict[str, Any]) -> str:
    """Formats the reconnaissance results into an executive, terminal-style text report."""
    target = data.get("target", {})
    network = data.get("network", {})
    web = data.get("web", {})
    headers = data.get("headers", {})
    technologies = data.get("technologies", [])
    endpoints = data.get("endpoints", {})
    robots = data.get("robots", {})
    sitemap = data.get("sitemap", {})
    methods = data.get("http_methods", {})
    timestamp = data.get("timestamp", "")
    metadata = data.get("metadata", {})

    lines = []
    lines.append("=" * 74)
    lines.append("  GRAYSENTINEL CYBER DEFENCE LAB — DAY 1 PROJECT 01")
    lines.append("  AUTHORIZED WEB RECONNAISSANCE & ENUMERATION REPORT")
    lines.append("=" * 74)
    lines.append(f"  Candidate   : {metadata.get('candidate', 'Mrunal Urankar')}")
    lines.append(f"  Team        : {metadata.get('team', 'Red Team')}")
    lines.append(f"  Project     : {metadata.get('project', 'Project 01 — Authorized Web Recon & Enumeration')}")
    lines.append(f"  Standard    : Assigned -> Built -> Tested -> Documented -> Published -> Proven")
    lines.append(f"  Timestamp   : {timestamp}")
    lines.append("-" * 74)
    lines.append("  [!] AUTHORIZATION & SCOPE STATEMENT:")
    lines.append("  This reconnaissance activity was conducted strictly against an authorized")
    lines.append("  controlled lab target. It uses passive and conservative observation techniques.")
    lines.append("  Missing headers or exposed paths are documented as security observations,")
    lines.append("  NOT as confirmed vulnerabilities. No exploitative payloads were transmitted.")
    lines.append("=" * 74)
    lines.append("")

    # 1. Target Information
    lines.append("1. TARGET IDENTIFICATION")
    lines.append("-" * 40)
    lines.append(f"  Target URL       : {target.get('normalized_url')}")
    lines.append(f"  Hostname         : {target.get('hostname')}")
    lines.append(f"  Resolved IP      : {target.get('resolved_ip')}")
    lines.append(f"  Protocol         : {target.get('protocol', '').upper()}")
    lines.append(f"  Port             : {target.get('port')}")
    lines.append(f"  Scope Validation : {target.get('authorization_status')}")
    lines.append("")

    # 2. Port & Service Enumeration
    lines.append("2. CONTROLLED PORT & SERVICE DISCOVERY")
    lines.append("-" * 40)
    ports_list = network.get("ports", [])
    if ports_list:
        lines.append(f"  {'PORT':<8} | {'STATE':<10} | {'SERVICE':<28} | {'LATENCY':<10}")
        lines.append("  " + "-" * 62)
        for p in ports_list:
            latency_str = f"{p.get('latency_ms')} ms"
            lines.append(f"  {p.get('port'):<8} | {p.get('state'):<10} | {p.get('service')[:28]:<28} | {latency_str:<10}")
            if p.get("banner"):
                lines.append(f"    └── Banner: {p.get('banner')}")
    else:
        lines.append("  Port scan was bypassed (--no-port-scan).")
    lines.append("")

    # 3. HTTP Service Enumeration
    lines.append("3. HTTP / HTTPS SERVICE ENUMERATION")
    lines.append("-" * 40)
    lines.append(f"  HTTP Status Code : {web.get('status_code')} ({web.get('status_message')})")
    lines.append(f"  Response Time    : {web.get('response_time_ms')} ms")
    lines.append(f"  Content-Type     : {web.get('content_type') or 'None declared'}")
    lines.append(f"  Content-Length   : {web.get('content_length')} bytes")
    lines.append(f"  Server Header    : {web.get('server_header')}")
    lines.append(f"  HTML Title       : {web.get('html_title') or 'None detected'}")
    lines.append(f"  Final URL        : {web.get('final_url')}")
    lines.append(f"  Redirect Count   : {web.get('redirect_count', 0)}")
    if web.get("redirects"):
        for red in web.get("redirects", []):
            lines.append(f"    Redirect: {red.get('status_code')} -> {red.get('to_url')}")
    if methods.get("allowed_methods"):
        lines.append(f"  Allowed Methods  : {', '.join(methods.get('allowed_methods'))}")
    lines.append("")

    # 4. Security Header Analysis
    lines.append("4. SECURITY HEADER ANALYSIS (OBSERVATIONS ONLY)")
    lines.append("-" * 40)
    lines.append("  * Note: Absence indicates a defense-in-depth observation, NOT a verified vulnerability.")
    lines.append("")
    header_details = headers.get("details", [])
    for h in header_details:
        status_symbol = "[+]" if h.get("status") == "PRESENT" else "[-]"
        lines.append(f"  {status_symbol} {h.get('header')}: {h.get('status')}")
        lines.append(f"      Observed : {h.get('observation')}")
        lines.append(f"      Context  : {h.get('why_it_matters')}")
        lines.append(f"      Scope    : {h.get('limitation_context')}")
        lines.append("")

    # 5. Technology Identification
    lines.append("5. PASSIVE TECHNOLOGY IDENTIFICATION")
    lines.append("-" * 40)
    if technologies:
        for tech in technologies:
            lines.append(f"  * {tech.get('name')} [{tech.get('category')}]")
            lines.append(f"    Confidence: {tech.get('confidence')}")
            lines.append(f"    Evidence  : {tech.get('evidence')}")
    else:
        lines.append("  No prominent framework or server signatures observed.")
    lines.append("")

    # 6. Robots.txt and Sitemap
    lines.append("6. ROBOTS.TXT & SITEMAP DISCOVERY")
    lines.append("-" * 40)
    lines.append(f"  /robots.txt : {'FOUND (HTTP 200)' if robots.get('present') else 'NOT PRESENT'}")
    parsed_robots = robots.get("parsed", {})
    if parsed_robots.get("disallowed_paths"):
        lines.append("    Disallowed Paths (Informational):")
        for dp in parsed_robots.get("disallowed_paths"):
            lines.append(f"      - {dp}")
    lines.append(f"  /sitemap.xml: {'FOUND (HTTP 200)' if sitemap.get('present') else 'NOT PRESENT'}")
    if sitemap.get("urls_discovered"):
        lines.append(f"    URLs indexed: {sitemap.get('url_count')}")
    lines.append("")

    # 7. Endpoint Enumeration
    lines.append("7. CONTROLLED WEB ENDPOINT ENUMERATION")
    lines.append("-" * 40)
    endpoint_items = endpoints.get("endpoints", [])
    if endpoint_items:
        lines.append(f"  {'STATUS':<8} | {'LENGTH':<10} | {'CATEGORY':<28} | {'PATH'}")
        lines.append("  " + "-" * 66)
        for ep in endpoint_items:
            status_disp = str(ep.get("status_code")) if ep.get("status_code") else "ERR"
            length_disp = f"{ep.get('content_length')} B" if ep.get("content_length") is not None else "-"
            lines.append(f"  {status_disp:<8} | {length_disp:<10} | {ep.get('category')[:28]:<28} | {ep.get('path')}")
            if ep.get("redirect_to"):
                lines.append(f"    └── Redirects to: {ep.get('redirect_to')}")
    else:
        lines.append("  Endpoint enumeration was bypassed (--no-endpoint-enum).")
    lines.append("")

    lines.append("=" * 74)
    lines.append("  END OF RECONNAISSANCE REPORT — EVIDENCE GENERATED FOR REVIEW")
    lines.append("=" * 74)
    return "\n".join(lines)


def write_reports(data: Dict[str, Any], output_dir: str = "output") -> Dict[str, str]:
    """Writes both recon.json and recon.txt into the specified output directory."""
    os.makedirs(output_dir, exist_ok=True)

    json_path = os.path.join(output_dir, "recon.json")
    text_path = os.path.join(output_dir, "recon.txt")

    json_content = build_json_report(data)
    text_content = build_text_report(data)

    with open(json_path, "w", encoding="utf-8") as f:
        f.write(json_content)

    with open(text_path, "w", encoding="utf-8") as f:
        f.write(text_content)

    return {
        "json_path": json_path,
        "text_path": text_path
    }
