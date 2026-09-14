"""
Tests for FindingValidator: schema checks, policy enforcement, and evidence rules.
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
    EvidenceItem,
    Remediation,
    Severity,
    Confidence,
    ValidationStatus,
)
from gray_sentinel.validator import FindingValidator


class TestValidator(unittest.TestCase):

    def setUp(self):
        self.validator = FindingValidator()
        self.valid_finding = Finding(
            id="GS-SEC-001",
            title="Public Exposure of Database Port",
            description="Direct network exposure of port 3306 on target perimeter allows unauthorized access.",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            affected_asset="lab.internal:3306",
            cvss_score=7.5,
            reproduction_steps=["Issue TCP connect probe to port 3306", "Verify handshake banner received"],
            evidence=[
                EvidenceItem(id="EVD-01", source="Port Probe", observation="Port 3306 open")
            ],
            remediation=Remediation(
                tactical="Block port 3306 in perimeter firewall.",
                strategic="Place database servers on isolated private subnets."
            )
        )

    def test_valid_finding_passes(self):
        res = self.validator.validate_finding(self.valid_finding)
        self.assertTrue(res.is_valid)
        self.assertEqual(len(res.errors), 0)

    def test_missing_or_empty_id(self):
        self.valid_finding.id = ""
        res = self.validator.validate_finding(self.valid_finding)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("id is empty" in e.lower() for e in res.errors))

    def test_empty_or_short_title(self):
        self.valid_finding.title = "Bad"
        res = self.validator.validate_finding(self.valid_finding)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("title must be at least" in e.lower() for e in res.errors))

    def test_brief_description_rejected(self):
        self.valid_finding.description = "Too short."
        res = self.validator.validate_finding(self.valid_finding)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("description too brief" in e.lower() for e in res.errors))

    def test_critical_or_high_requires_evidence(self):
        self.valid_finding.severity = Severity.CRITICAL
        self.valid_finding.evidence = []  # policy violation
        res = self.validator.validate_finding(self.valid_finding)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("must have at least one supporting evidence" in e.lower() for e in res.errors))

    def test_cvss_score_out_of_bounds(self):
        self.valid_finding.cvss_score = 10.5
        res = self.validator.validate_finding(self.valid_finding)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("out of bounds" in e.lower() for e in res.errors))

    def test_insufficient_reproduction_steps_warning(self):
        self.valid_finding.reproduction_steps = ["Only single step"]
        res = self.validator.validate_finding(self.valid_finding)
        # Should remain valid but yield warning
        self.assertTrue(res.is_valid)
        self.assertTrue(any("insufficient reproduction steps" in w.lower() for w in res.warnings))

    def test_duplicate_id_detection_in_validate_all(self):
        f1 = self.valid_finding
        f2 = Finding(
            id="GS-SEC-001",  # duplicate ID
            title="Another Finding With Same ID",
            description="Legitimate description exceeding minimum required character length.",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            affected_asset="https://lab.internal/",
            cvss_score=2.0,
        )
        results = self.validator.validate_all([f1, f2])
        self.assertTrue(results[0].is_valid)
        self.assertFalse(results[1].is_valid)
        self.assertTrue(any("duplicate" in e.lower() for e in results[1].errors))


if __name__ == "__main__":
    unittest.main()
