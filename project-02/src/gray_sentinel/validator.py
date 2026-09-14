"""
GraySentinel Project 02: Finding Validation Engine.
Applies rigorous schema checks, security policy validation, evidence requirements,
and reproduction depth verification to all candidate findings.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple
from .models import Finding, Severity, Confidence, ValidationStatus


@dataclass
class FindingValidationResult:
    """Individual finding validation record."""
    finding_id: str
    title: str
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def status_symbol(self) -> str:
        if not self.is_valid:
            return "✗"
        if self.warnings:
            return "⚠"
        return "✔"


class FindingValidator:
    """
    Validates findings according to GraySentinel security reporting standards.
    Enforces required fields, evidence presence for high/critical findings,
    minimum description depth, reproduction steps, and duplicate ID prevention.
    """

    MIN_DESCRIPTION_LENGTH = 25
    MIN_REPRODUCTION_STEPS = 2

    def validate_finding(self, finding: Finding) -> FindingValidationResult:
        """Validates a single Finding instance against schema and policy rules."""
        errors: List[str] = []
        warnings: List[str] = []

        # 1. Required identifier & format
        if not finding.id or not finding.id.strip():
            errors.append("Finding ID is empty or missing.")
        elif not (finding.id.startswith("GS-SEC-") or finding.id.startswith("F")):
            warnings.append(f"Non-standard ID format '{finding.id}'. Expected prefix 'GS-SEC-' or 'F'.")

        # 2. Required title
        if not finding.title or len(finding.title.strip()) < 5:
            errors.append("Title must be at least 5 characters long.")

        # 3. Required description depth
        if not finding.description or len(finding.description.strip()) < self.MIN_DESCRIPTION_LENGTH:
            errors.append(
                f"Description too brief ({len(finding.description or '')} chars). "
                f"Must be at least {self.MIN_DESCRIPTION_LENGTH} characters."
            )

        # 4. Severity & Confidence type validation
        if not isinstance(finding.severity, Severity):
            errors.append(f"Invalid severity type: {type(finding.severity)}. Must be Severity enum.")

        if not isinstance(finding.confidence, Confidence):
            errors.append(f"Invalid confidence type: {type(finding.confidence)}. Must be Confidence enum.")

        # 5. Affected Asset check
        if not finding.affected_asset or not finding.affected_asset.strip():
            errors.append("Affected asset (URL, domain, or parameter) is required.")

        # 6. CVSS score range check
        if finding.cvss_score < 0.0 or finding.cvss_score > 10.0:
            errors.append(f"CVSS score {finding.cvss_score} is out of bounds (0.0 - 10.0).")

        # 7. Evidence Requirement for CRITICAL and HIGH findings
        if finding.severity in (Severity.CRITICAL, Severity.HIGH):
            if not finding.evidence or len(finding.evidence) == 0:
                errors.append(
                    f"Policy violation: Findings with severity '{finding.severity.value}' "
                    "MUST have at least one supporting evidence item attached."
                )
            else:
                unverified_count = sum(1 for e in finding.evidence if not e.observation)
                if unverified_count > 0:
                    warnings.append(f"{unverified_count} evidence item(s) lack observation text.")

        # 8. Reproduction Steps verification
        if not finding.reproduction_steps or len(finding.reproduction_steps) < self.MIN_REPRODUCTION_STEPS:
            warnings.append(
                f"Insufficient reproduction steps ({len(finding.reproduction_steps)} provided). "
                f"Minimum {self.MIN_REPRODUCTION_STEPS} sequential steps recommended for audit reproducibility."
            )

        # 9. Remediation completeness
        if not finding.remediation:
            warnings.append("No remediation recommendations attached to finding.")
        else:
            if not finding.remediation.tactical:
                warnings.append("Remediation lacks tactical immediate action steps.")
            if not finding.remediation.strategic:
                warnings.append("Remediation lacks strategic long-term guidance.")

        is_valid = len(errors) == 0
        return FindingValidationResult(
            finding_id=finding.id,
            title=finding.title,
            is_valid=is_valid,
            errors=errors,
            warnings=warnings,
        )

    def validate_all(self, findings: List[Finding]) -> List[FindingValidationResult]:
        """
        Validates a list of findings and detects duplicate identifiers across the set.
        """
        results: List[FindingValidationResult] = []
        seen_ids: Dict[str, int] = {}

        for f in findings:
            res = self.validate_finding(f)

            # Check duplicate ID
            if f.id in seen_ids:
                seen_ids[f.id] += 1
                res.is_valid = False
                res.errors.append(f"Duplicate finding identifier '{f.id}' detected in dataset.")
            else:
                seen_ids[f.id] = 1

            results.append(res)

        return results
