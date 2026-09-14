"""
GraySentinel Project 02: Remediation Recommendation Generator and Roadmap Engine.
Transforms technical security findings into actionable, contextual remediation plans
split into tactical (immediate) actions, strategic engineering, and phased roadmaps.
"""

from typing import List, Dict, Any
from .models import Finding, Severity, Remediation


class RemediationEngine:
    """Provides remediation synthesis and multi-phase roadmap sequencing."""

    @staticmethod
    def ensure_remediation(finding: Finding) -> Remediation:
        """
        Ensures a finding has a high-quality contextual remediation recommendation attached.
        If already defined, returns it; otherwise synthesizes targeted guidance based on CWE/OWASP/Title.
        """
        if finding.remediation and finding.remediation.tactical:
            return finding.remediation

        title_lower = finding.title.lower()
        asset = finding.affected_asset

        if "header" in title_lower:
            rem = Remediation(
                tactical=(
                    f"Configure reverse proxy serving '{asset}' to inject HSTS, CSP, "
                    "X-Content-Type-Options, and X-Frame-Options headers."
                ),
                strategic=(
                    "Implement a centralized reverse proxy header policy template across all "
                    "microservices and integrate automated header checks into CI/CD pipelines."
                ),
                code_example=(
                    "add_header Content-Security-Policy \"default-src 'self';\" always;\n"
                    "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
                    "add_header X-Frame-Options \"DENY\" always;\n"
                    "add_header X-Content-Type-Options \"nosniff\" always;"
                ),
                references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"],
            )
        elif any(k in title_lower for k in ["config", "env", "git", "secret", "exposure"]):
            rem = Remediation(
                tactical=(
                    f"Immediately restrict external access to '{asset}', invalidate all credentials "
                    "found within exposed files, and issue new production secrets."
                ),
                strategic=(
                    "Implement pre-commit secret detection (e.g., git-secrets, truffleHog), remove "
                    "all dotfiles and backups from web server roots, and store secrets in a dedicated vault."
                ),
                code_example="location ~ /\\.(?!well-known).* { deny all; return 404; }",
                references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
            )
        elif any(k in title_lower for k in ["port", "database", "management", "ssh"]):
            rem = Remediation(
                tactical=(
                    f"Apply network firewall access control lists (ACLs) to block direct inbound "
                    f"traffic to '{asset}' from untrusted IP ranges."
                ),
                strategic=(
                    "Enforce private VPC peering and mandate multi-factor VPN or identity-aware "
                    "bastion proxies for all database and administrative plane connectivity."
                ),
                code_example="iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 3306 -j ACCEPT\niptables -A INPUT -p tcp --dport 3306 -j DROP",
                references=["https://cwe.mitre.org/data/definitions/1188.html"],
            )
        elif any(k in title_lower for k in ["admin", "debug", "console", "actuator"]):
            rem = Remediation(
                tactical=(
                    f"Gate access to '{asset}' behind enterprise single sign-on (SSO) with MFA "
                    "and restrict access to internal corporate subnets."
                ),
                strategic=(
                    "Decommission development debug consoles from production builds and adopt "
                    "role-based access control (RBAC) governance across all administrative endpoints."
                ),
                references=["https://cwe.mitre.org/data/definitions/284.html"],
            )
        else:
            rem = Remediation(
                tactical=f"Review configuration and access permissions governing '{asset}'.",
                strategic="Incorporate threat modeling and secure architecture reviews into the SDLC.",
                references=["https://owasp.org/www-project-top-ten/"],
            )

        finding.remediation = rem
        return rem

    @staticmethod
    def build_action_roadmap(findings: List[Finding]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Groups findings into a prioritized 3-phase remediation schedule:
          - Phase 1: Emergency Tactical Remediation (0 - 48 Hours)
          - Phase 2: Systematic Access Controls & Hardening (3 - 14 Days)
          - Phase 3: Defensive Governance & Hygiene (15 - 30 Days)
        """
        phase_1: List[Dict[str, Any]] = []
        phase_2: List[Dict[str, Any]] = []
        phase_3: List[Dict[str, Any]] = []

        for f in findings:
            remediation = RemediationEngine.ensure_remediation(f)
            item = {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "asset": f.affected_asset,
                "tactical": remediation.tactical,
                "strategic": remediation.strategic,
                "code_example": remediation.code_example,
            }

            if f.severity == Severity.CRITICAL:
                phase_1.append(item)
            elif f.severity == Severity.HIGH:
                phase_1.append(item)
            elif f.severity == Severity.MEDIUM:
                phase_2.append(item)
            else:
                phase_3.append(item)

        return {
            "phase_1_immediate_0_48h": phase_1,
            "phase_2_tactical_3_14d": phase_2,
            "phase_3_strategic_15_30d": phase_3,
        }
