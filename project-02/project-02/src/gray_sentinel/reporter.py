"""
GraySentinel Project 02: Markdown Security Report Generator.
Renders audit-grade, publication-ready security assessment reports conforming to
the GraySentinel 11-section reporting standard.
"""

import datetime
import os
from typing import List, Optional
from .models import Finding, ReconData, Severity, ValidationStatus
from .risk import RiskAnalyzer, RiskSummary
from .remediation import RemediationEngine
from .errors import ReportGenerationError


class ReportGenerator:
    """Generates comprehensive Markdown assessment documentation."""

    @staticmethod
    def generate_markdown_report(
        findings: List[Finding],
        recon: Optional[ReconData] = None,
        auditor_name: str = "GraySentinel Security Team",
        engagement_id: Optional[str] = None,
    ) -> str:
        """Assembles the complete 11-section security assessment report."""
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        is_demo = recon.is_demo if recon else any(
            any(e.is_demo_sample for e in f.evidence) for f in findings
        )
        data_class_label = "SANITIZED DEMO DATA — NOT A REAL TARGET" if is_demo else "AUTHORIZED LAB DATA — EXPLICIT PERMISSION"

        total_endpoints = len(recon.endpoints) if recon else max(len(findings), 1)
        risk_summary: RiskSummary = RiskAnalyzer.calculate_summary(findings, total_endpoints=total_endpoints)
        roadmap = RemediationEngine.build_action_roadmap(findings)

        target_name = recon.target if recon else (findings[0].affected_asset if findings else "Target Web Environment")
        eng_id = engagement_id or (recon.scan_id if recon else f"GS-ENG-{datetime.date.today().strftime('%Y%m%d')}")

        report_lines: List[str] = []

        # Header Block
        report_lines.append("# GraySentinel Web Security Assessment Report")
        report_lines.append("")
        report_lines.append(f"> **DATA CLASSIFICATION:** {data_class_label}  ")
        report_lines.append(f"> **ENGAGEMENT ID:** `{eng_id}` | **TARGET:** `{target_name}` | **DATE:** {now}  ")
        report_lines.append(f"> **AUDITOR / LEAD:** {auditor_name} | **STATUS:** FINAL ASSESSMENT")
        report_lines.append("")
        report_lines.append("---")
        report_lines.append("")

        # 1. Executive Summary
        report_lines.append("## 1. Executive Summary")
        report_lines.append("")
        report_lines.append(
            f"GraySentinel performed a structured web application and perimeter security evaluation against "
            f"**`{target_name}`**. The primary objective was to validate attack surface exposure, analyze "
            f"correlations from reconnaissance telemetry, and establish an actionable risk remediation roadmap."
        )
        report_lines.append("")
        report_lines.append(
            f"A total of **{risk_summary.total_findings} finding(s)** were identified, validated, and categorized. "
            f"The overall security posture is evaluated as **{risk_summary.posture_rating}** with a cumulative "
            f"weighted risk score of **{risk_summary.weighted_risk_score}**."
        )
        report_lines.append("")
        report_lines.append(f"**Posture Diagnosis:** {risk_summary.posture_description}")
        report_lines.append("")

        # 2. Scope
        report_lines.append("## 2. Scope")
        report_lines.append("")
        report_lines.append("The scope of this assessment was bounded strictly by the following assets:")
        report_lines.append("")
        report_lines.append(f"- **Primary Target Host:** `{target_name}`")
        if recon:
            report_lines.append(f"- **Reconnaissance Scan ID:** `{recon.scan_id}`")
            report_lines.append(f"- **Scan Ingestion Timestamp:** `{recon.timestamp}`")
            report_lines.append(f"- **Discovered Network Ports:** {len(recon.open_ports)} exposed port(s)")
            report_lines.append(f"- **Enumerated Web Endpoints:** {len(recon.endpoints)} route(s)")
        report_lines.append("")
        report_lines.append(
            "All assessment activities were conducted strictly in compliance with GraySentinel Rules of "
            "Engagement. No denial-of-service, invasive exploitation, or uncoordinated perimeter attacks occurred."
        )
        report_lines.append("")

        # 3. Methodology
        report_lines.append("## 3. Methodology")
        report_lines.append("")
        report_lines.append(
            "Assessments adhere to the **GraySentinel Threat-First Validation Methodology**, comprising four distinct phases:"
        )
        report_lines.append("")
        report_lines.append(
            "1. **Reconnaissance Ingestion & Attack Surface Correlation:** Ingestion of standardized JSON "
            "reconnaissance telemetry from Project 01, mapping open ports, endpoints, and HTTP response headers.\n"
            "2. **Evidence Cryptographic Verification:** Generating and cross-referencing SHA-256 integrity digests "
            "for proof-of-concept artifacts to prevent tampering and ensure verifiable auditing.\n"
            "3. **Schema & Policy Validation:** Enforcing strict schema rules, mandatory reproduction steps, and "
            "evidence requirements for high/critical findings.\n"
            "4. **Risk Quantification & Phased Roadmapping:** Calculating weighted risk metrics "
            "(`Severity Weight × Confidence Multiplier`) and deriving a 3-phase remediation schedule."
        )
        report_lines.append("")

        # 4. Assets Reviewed
        report_lines.append("## 4. Assets Reviewed")
        report_lines.append("")
        if recon and recon.endpoints:
            report_lines.append("| Endpoint / Resource | HTTP Status | Method | Content Type | Exposure / Notes |")
            report_lines.append("| :--- | :---: | :---: | :--- | :--- |")
            for ep in recon.endpoints:
                report_lines.append(
                    f"| `{ep.path}` | `{ep.status_code}` | `{ep.method}` | `{ep.content_type}` | {ep.title or 'Standard Route'} |"
                )
            report_lines.append("")
        else:
            report_lines.append(f"- Target asset reviewed: `{target_name}`")
            report_lines.append("")

        if recon and recon.open_ports:
            report_lines.append("### Discovered Network Services")
            report_lines.append("")
            report_lines.append("| Port | Protocol | Service | State | Identified Banner |")
            report_lines.append("| :---: | :---: | :--- | :---: | :--- |")
            for p in recon.open_ports:
                report_lines.append(f"| `{p.port}` | `{p.protocol}` | `{p.service}` | `{p.state}` | `{p.banner or 'None'}` |")
            report_lines.append("")

        # 5. Severity Summary
        report_lines.append("## 5. Severity Summary")
        report_lines.append("")
        report_lines.append("| Severity Level | Count | Weight Factor | Impact Description |")
        report_lines.append("| :--- | :---: | :---: | :--- |")
        report_lines.append(f"| **CRITICAL** | `{risk_summary.by_severity.get('CRITICAL', 0)}` | 10.0 | Immediate systemic compromise or credential exposure |")
        report_lines.append(f"| **HIGH** | `{risk_summary.by_severity.get('HIGH', 0)}` | 7.0 | Direct attack surface or significant authorization bypass |")
        report_lines.append(f"| **MEDIUM** | `{risk_summary.by_severity.get('MEDIUM', 0)}` | 4.0 | Administrative interface exposure or perimeter hygiene flaw |")
        report_lines.append(f"| **LOW** | `{risk_summary.by_severity.get('LOW', 0)}` | 1.0 | Absence of defensive HTTP response headers |")
        report_lines.append(f"| **INFO** | `{risk_summary.by_severity.get('INFO', 0)}` | 0.0 | Informational observation |")
        report_lines.append(f"| **Total Findings** | **`{risk_summary.total_findings}`** | — | **Weighted Score: {risk_summary.weighted_risk_score}** |")
        report_lines.append("")

        # 6. Detailed Findings
        report_lines.append("## 6. Detailed Findings")
        report_lines.append("")
        if not findings:
            report_lines.append("No security vulnerabilities were identified in the assessed target dataset.")
            report_lines.append("")
        else:
            for idx, f in enumerate(findings, 1):
                report_lines.append(f"### 6.{idx}. [{f.id}] {f.title}")
                report_lines.append("")
                report_lines.append(f"- **Severity:** `{f.severity.value}` | **Confidence:** `{f.confidence.value}` | **Status:** `{f.validation_status.value}`")
                report_lines.append(f"- **Affected Asset:** `{f.affected_asset}`")
                report_lines.append(f"- **CVSS v3.1 Score:** `{f.cvss_score}` (`{f.cvss_vector or 'N/A'}`)")
                report_lines.append(f"- **Classification:** `{f.cwe_id or 'CWE-N/A'}` ({f.cwe_name or 'N/A'}) | `{f.owasp_category or 'OWASP-N/A'}`")
                report_lines.append(f"- **Weighted Risk Points:** `{f.weighted_risk}`")
                report_lines.append("")
                report_lines.append("#### Description")
                report_lines.append(f.description)
                report_lines.append("")
                report_lines.append("#### Reproduction Steps")
                if f.reproduction_steps:
                    for s_idx, step in enumerate(f.reproduction_steps, 1):
                        report_lines.append(f"{s_idx}. {step}")
                else:
                    report_lines.append("1. Consult attached evidence artifact for reproduction procedure.")
                report_lines.append("")

                if f.evidence:
                    report_lines.append("#### Supporting Evidence")
                    for ev in f.evidence:
                        ev_class = "DEMO / SAMPLE DATA" if ev.is_demo_sample else "REAL LAB EVIDENCE"
                        report_lines.append(f"- **Evidence ID:** `{ev.id}` ({ev_class})")
                        report_lines.append(f"  - **Source:** {ev.source}")
                        report_lines.append(f"  - **Observation:** {ev.observation}")
                        if ev.sha256_hash:
                            report_lines.append(f"  - **SHA-256 Digest:** `{ev.sha256_hash}`")
                        if ev.relevant_data:
                            report_lines.append("  - **Payload / Response Snippet:**")
                            report_lines.append("    ```text")
                            report_lines.append(f"    {ev.relevant_data.strip()}")
                            report_lines.append("    ```")
                    report_lines.append("")

                rem = RemediationEngine.ensure_remediation(f)
                report_lines.append("#### Remediation Guidance")
                report_lines.append(f"- **Tactical Action:** {rem.tactical}")
                report_lines.append(f"- **Strategic Fix:** {rem.strategic}")
                if rem.code_example:
                    report_lines.append("```bash")
                    report_lines.append(rem.code_example.strip())
                    report_lines.append("```")
                report_lines.append("")

        # 7. Evidence
        report_lines.append("## 7. Evidence & Cryptographic Verification")
        report_lines.append("")
        report_lines.append(
            "Every high and critical finding documented in this report is bound to empirical evidence. "
            "Proof-of-concept artifacts are indexed with SHA-256 digests to ensure non-repudiation."
        )
        report_lines.append("")
        all_ev = [ev for f in findings for ev in f.evidence]
        if all_ev:
            report_lines.append("| Evidence ID | Finding ID | Source | SHA-256 Digest | Data Classification |")
            report_lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for f in findings:
                for ev in f.evidence:
                    hash_disp = f"`{ev.sha256_hash[:16]}...`" if ev.sha256_hash else "*Observation-Only*"
                    ev_type = "DEMO / SAMPLE" if ev.is_demo_sample else "REAL LAB"
                    report_lines.append(f"| `{ev.id}` | `{f.id}` | {ev.source} | {hash_disp} | {ev_type} |")
            report_lines.append("")
        else:
            report_lines.append("No binary artifacts attached; findings supported via observational headers.")
            report_lines.append("")

        # 8. Risk Assessment
        report_lines.append("## 8. Risk Assessment")
        report_lines.append("")
        report_lines.append(
            f"The overall environment risk posture is scored at **{risk_summary.posture_rating}** "
            f"({risk_summary.weighted_risk_score} points). Vulnerability density across discovered endpoints is "
            f"**{risk_summary.attack_surface_density} finding(s) per endpoint**."
        )
        report_lines.append("")
        report_lines.append(
            "Confidence-weighted metrics verify that critical exposure points are confirmed and actionable, "
            "warranting prioritized engineering attention."
        )
        report_lines.append("")

        # 9. Remediation Recommendations & Roadmap
        report_lines.append("## 9. Remediation Recommendations")
        report_lines.append("")
        report_lines.append("Remediation activities must follow this 3-phase chronological sequence:")
        report_lines.append("")
        report_lines.append("### Phase 1: Emergency Tactical Remediation (0 - 48 Hours)")
        if roadmap["phase_1_immediate_0_48h"]:
            for item in roadmap["phase_1_immediate_0_48h"]:
                report_lines.append(f"- **[{item['id']}] {item['title']}** (`{item['asset']}`): {item['tactical']}")
        else:
            report_lines.append("- No Phase 1 emergency interventions required.")
        report_lines.append("")

        report_lines.append("### Phase 2: Systematic Hardening & Access Control (3 - 14 Days)")
        if roadmap["phase_2_tactical_3_14d"]:
            for item in roadmap["phase_2_tactical_3_14d"]:
                report_lines.append(f"- **[{item['id']}] {item['title']}** (`{item['asset']}`): {item['tactical']}")
        else:
            report_lines.append("- No Phase 2 items scheduled.")
        report_lines.append("")

        report_lines.append("### Phase 3: Defensive Governance & Hygiene (15 - 30 Days)")
        if roadmap["phase_3_strategic_15_30d"]:
            for item in roadmap["phase_3_strategic_15_30d"]:
                report_lines.append(f"- **[{item['id']}] {item['title']}** (`{item['asset']}`): {item['strategic']}")
        else:
            report_lines.append("- No Phase 3 items scheduled.")
        report_lines.append("")

        # 10. Limitations
        report_lines.append("## 10. Limitations")
        report_lines.append("")
        report_lines.append(
            "- **Non-Destructive Constraint:** Testing was conducted non-destructively; no exploits were executed to achieve remote code execution.\n"
            "- **Time-Bounded Scope:** Findings reflect the security posture at the exact moment of reconnaissance ingestion.\n"
            "- **Data Classification Transparency:** Sample datasets are explicitly demarcated to prevent mistaking simulation for live operational assessments.\n"
            "- **No Third-Party Targets:** In strict adherence to GraySentinel policy, only explicitly authorized lab environments or sanitized fixtures were evaluated."
        )
        report_lines.append("")

        # 11. Conclusion
        report_lines.append("## 11. Conclusion")
        report_lines.append("")
        report_lines.append(
            f"The evaluation against `{target_name}` yielded high-fidelity, reproducible findings. "
            f"By executing the prioritized 3-phase remediation plan—specifically resolving public configuration "
            f"artifacts and deploying defensive HTTP headers—the target environment's risk rating will decrease "
            f"from **{risk_summary.posture_rating}** to **LOW RISK**."
        )
        report_lines.append("")
        report_lines.append("---")
        report_lines.append("*Report generated by GraySentinel Project 02: Web Security Findings Reporter.*")

        return "\n".join(report_lines)

    @staticmethod
    def save_report(
        markdown_text: str,
        output_filepath: str,
    ) -> str:
        """Saves the generated markdown report to disk."""
        try:
            os.makedirs(os.path.dirname(output_filepath), exist_ok=True)
            with open(output_filepath, "w", encoding="utf-8") as f:
                f.write(markdown_text)
            return os.path.abspath(output_filepath)
        except Exception as exc:
            raise ReportGenerationError(
                message=f"Failed to write security report to '{output_filepath}'",
                reason=str(exc),
                suggested_action="Verify write permissions for target report destination."
            )
