"""
Tests for ReportGenerator: 11-section markdown generation and file export.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure src directory is in sys.path
_src = Path(__file__).resolve().parent.parent / "src"
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

from gray_sentinel.models import (
    Finding,
    EvidenceItem,
    Severity,
    Confidence,
    ValidationStatus,
)
from gray_sentinel.reporter import ReportGenerator


class TestReporter(unittest.TestCase):

    def setUp(self):
        self.finding = Finding(
            id="GS-SEC-001",
            title="Exposed Database Port",
            description="Database port 3306 reachable from perimeter.",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            affected_asset="lab.internal:3306",
            cvss_score=7.5,
            validation_status=ValidationStatus.VALIDATED,
            reproduction_steps=["Step 1: Test port", "Step 2: Check response"],
            evidence=[
                EvidenceItem(
                    id="EVD-01",
                    source="Port Sweep",
                    observation="Port 3306 open",
                    is_demo_sample=True,
                )
            ],
        )

    def test_generate_markdown_content_and_sections(self):
        md = ReportGenerator.generate_markdown_report([self.finding])

        # Verify all 11 required sections exist
        required_sections = [
            "1. Executive Summary",
            "2. Scope",
            "3. Methodology",
            "4. Assets Reviewed",
            "5. Severity Summary",
            "6. Detailed Findings",
            "7. Evidence & Cryptographic Verification",
            "8. Risk Assessment",
            "9. Remediation Recommendations",
            "10. Limitations",
            "11. Conclusion",
        ]

        for sec in required_sections:
            self.assertIn(sec, md, f"Section '{sec}' missing from generated markdown report.")

        # Verify data classification tag
        self.assertIn("SANITIZED DEMO DATA", md)
        self.assertIn("GS-SEC-001", md)
        self.assertIn("Phase 1: Emergency Tactical Remediation", md)

    def test_save_markdown_report(self):
        md = ReportGenerator.generate_markdown_report([self.finding])
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_file = os.path.join(tmp_dir, "test_report.md")
            saved_path = ReportGenerator.save_report(md, out_file)
            self.assertTrue(os.path.exists(saved_path))
            with open(saved_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("GraySentinel Web Security Assessment Report", content)


if __name__ == "__main__":
    unittest.main()
