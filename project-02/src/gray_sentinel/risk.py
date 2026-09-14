"""
GraySentinel Project 02: Risk Analysis and Posture Scoring Engine.
Calculates risk posture, severity distributions, confidence breakdowns,
weighted risk points, and attack surface vulnerability density.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any
from .models import Finding, Severity, Confidence, ValidationStatus


@dataclass
class RiskSummary:
    """Comprehensive risk evaluation outcome."""
    total_findings: int
    by_severity: Dict[str, int]
    by_confidence: Dict[str, int]
    by_status: Dict[str, int]
    weighted_risk_score: float
    posture_rating: str
    posture_description: str
    attack_surface_density: float = 0.0
    critical_or_high_count: int = 0
    validated_count: int = 0
    review_required_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "by_severity": self.by_severity,
            "by_confidence": self.by_confidence,
            "by_status": self.by_status,
            "weighted_risk_score": self.weighted_risk_score,
            "posture_rating": self.posture_rating,
            "posture_description": self.posture_description,
            "attack_surface_density": self.attack_surface_density,
            "critical_or_high_count": self.critical_or_high_count,
            "validated_count": self.validated_count,
            "review_required_count": self.review_required_count,
        }


class RiskAnalyzer:
    """
    Computes mathematical risk metrics and posture ratings from validated findings.
    Formula:
        Weighted Finding Score = Severity Weight * Confidence Multiplier
        Total Score = Sum(Weighted Finding Scores) excluding FALSE_POSITIVE
    """

    @staticmethod
    def calculate_summary(findings: List[Finding], total_endpoints: int = 1) -> RiskSummary:
        total = len(findings)

        by_sev: Dict[str, int] = {s.value: 0 for s in Severity}
        by_conf: Dict[str, int] = {c.value: 0 for c in Confidence}
        by_status: Dict[str, int] = {st.value: 0 for st in ValidationStatus}

        total_weighted = 0.0
        critical_or_high = 0

        for f in findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
            by_conf[f.confidence.value] = by_conf.get(f.confidence.value, 0) + 1
            by_status[f.validation_status.value] = by_status.get(f.validation_status.value, 0) + 1

            if f.severity in (Severity.CRITICAL, Severity.HIGH):
                critical_or_high += 1

            total_weighted += f.weighted_risk

        weighted_score = round(total_weighted, 2)
        validated_count = by_status.get(ValidationStatus.VALIDATED.value, 0)
        review_count = by_status.get(ValidationStatus.REVIEW.value, 0) + by_status.get(ValidationStatus.DRAFT.value, 0)

        # Posture classification
        if by_sev.get("CRITICAL", 0) > 0 or weighted_score >= 15.0:
            posture = "CRITICAL RISK"
            desc = "Immediate exploitation potential present. Perimeter or critical secrets exposed."
        elif by_sev.get("HIGH", 0) > 0 or weighted_score >= 8.0:
            posture = "HIGH RISK"
            desc = "Significant attack surface vulnerability. Remediation required prior to release."
        elif by_sev.get("MEDIUM", 0) > 0 or weighted_score >= 4.0:
            posture = "MODERATE RISK"
            desc = "Multiple medium-severity configuration or header hygiene flaws detected."
        elif total > 0:
            posture = "LOW RISK"
            desc = "Minor baseline hardening and security header deficiencies noted."
        else:
            posture = "SECURE / NEGLIGIBLE RISK"
            desc = "No actionable vulnerabilities identified during assessment."

        endpoints_divisor = max(total_endpoints, 1)
        density = round(total / endpoints_divisor, 2)

        return RiskSummary(
            total_findings=total,
            by_severity=by_sev,
            by_confidence=by_conf,
            by_status=by_status,
            weighted_risk_score=weighted_score,
            posture_rating=posture,
            posture_description=desc,
            attack_surface_density=density,
            critical_or_high_count=critical_or_high,
            validated_count=validated_count,
            review_required_count=review_count,
        )
