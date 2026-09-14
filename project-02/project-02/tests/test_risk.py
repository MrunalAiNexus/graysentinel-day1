"""
Tests for RiskAnalyzer: threat scoring, posture categorization, and metrics.
"""

import sys
import unittest
from pathlib import Path

# Ensure src directory is in sys.path
_src = Path(__file__).resolve().parent.parent / "src"
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

from gray_sentinel.models import (
    Finding,
    Severity,
    Confidence,
    ValidationStatus,
)
from gray_sentinel.risk import RiskAnalyzer


class TestRisk(unittest.TestCase):

    def test_empty_findings_posture(self):
        summary = RiskAnalyzer.calculate_summary([], total_endpoints=5)
        self.assertEqual(summary.total_findings, 0)
        self.assertEqual(summary.weighted_risk_score, 0.0)
        self.assertEqual(summary.posture_rating, "SECURE / NEGLIGIBLE RISK")
        self.assertEqual(summary.attack_surface_density, 0.0)

    def test_weighted_risk_calculation_and_posture(self):
        f1 = Finding(
            id="F01",
            title="Exposed Database",
            description="Exposed database port on perimeter.",
            severity=Severity.HIGH,       # weight 7.0
            confidence=Confidence.HIGH,   # multiplier 1.0 -> 7.0
            affected_asset="target:3306",
            validation_status=ValidationStatus.VALIDATED,
        )
        f2 = Finding(
            id="F02",
            title="Missing Security Headers",
            description="Defensive HTTP headers absent.",
            severity=Severity.LOW,        # weight 1.0
            confidence=Confidence.MEDIUM, # multiplier 0.7 -> 0.7
            affected_asset="https://target/",
            validation_status=ValidationStatus.VALIDATED,
        )
        summary = RiskAnalyzer.calculate_summary([f1, f2], total_endpoints=2)
        self.assertEqual(summary.total_findings, 2)
        self.assertEqual(summary.weighted_risk_score, 7.7)
        self.assertEqual(summary.posture_rating, "HIGH RISK")
        self.assertEqual(summary.attack_surface_density, 1.0)
        self.assertEqual(summary.validated_count, 2)

    def test_critical_finding_triggers_critical_risk(self):
        f_crit = Finding(
            id="F01",
            title="Environment Secrets Exposed",
            description="Exposed environment secrets file.",
            severity=Severity.CRITICAL,   # weight 10.0
            confidence=Confidence.HIGH,   # multiplier 1.0 -> 10.0
            affected_asset="https://target/.env",
            validation_status=ValidationStatus.VALIDATED,
        )
        summary = RiskAnalyzer.calculate_summary([f_crit], total_endpoints=1)
        self.assertEqual(summary.posture_rating, "CRITICAL RISK")
        self.assertEqual(summary.critical_or_high_count, 1)

    def test_false_positive_excluded_from_weight(self):
        f_fp = Finding(
            id="F01",
            title="Benign Header Flagged",
            description="Verified false positive observation.",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            affected_asset="https://target/",
            validation_status=ValidationStatus.FALSE_POSITIVE,
        )
        summary = RiskAnalyzer.calculate_summary([f_fp], total_endpoints=1)
        self.assertEqual(summary.weighted_risk_score, 0.0)


if __name__ == "__main__":
    unittest.main()
