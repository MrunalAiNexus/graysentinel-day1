"""
Tests for GraySentinel finding, evidence, and risk data models.
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


class TestModels(unittest.TestCase):

    def test_severity_weights_and_parsing(self):
        self.assertEqual(Severity.CRITICAL.weight, 10.0)
        self.assertEqual(Severity.HIGH.weight, 7.0)
        self.assertEqual(Severity.MEDIUM.weight, 4.0)
        self.assertEqual(Severity.LOW.weight, 1.0)
        self.assertEqual(Severity.INFO.weight, 0.0)

        self.assertEqual(Severity.from_str("critical"), Severity.CRITICAL)
        self.assertEqual(Severity.from_str("informational"), Severity.INFO)
        with self.assertRaises(ValueError):
            Severity.from_str("UNKNOWN_SEVERITY")

    def test_confidence_multipliers_and_parsing(self):
        self.assertEqual(Confidence.HIGH.multiplier, 1.0)
        self.assertEqual(Confidence.MEDIUM.multiplier, 0.7)
        self.assertEqual(Confidence.LOW.multiplier, 0.4)

        self.assertEqual(Confidence.from_str("confirmed"), Confidence.HIGH)
        self.assertEqual(Confidence.from_str("tentative"), Confidence.LOW)
        with self.assertRaises(ValueError):
            Confidence.from_str("INVALID_CONF")

    def test_weighted_risk_calculation(self):
        f = Finding(
            id="GS-SEC-001",
            title="Publicly Accessible Environment File",
            description="Environment variable configuration file exposed.",
            severity=Severity.CRITICAL,  # weight: 10.0
            confidence=Confidence.HIGH,  # multiplier: 1.0
            affected_asset="https://target/.env",
        )
        self.assertEqual(f.weighted_risk, 10.0)

        f_med = Finding(
            id="GS-SEC-002",
            title="Sensitive Debug Metrics Interface",
            description="Exposed internal debug metrics route.",
            severity=Severity.MEDIUM,    # weight: 4.0
            confidence=Confidence.MEDIUM,# multiplier: 0.7
            affected_asset="https://target/debug",
        )
        self.assertEqual(f_med.weighted_risk, 2.8)

        f_fp = Finding(
            id="GS-SEC-003",
            title="False Positive Header Issue",
            description="Flagged as false positive by auditor.",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            affected_asset="https://target/",
            validation_status=ValidationStatus.FALSE_POSITIVE,
        )
        self.assertEqual(f_fp.weighted_risk, 0.0)

    def test_finding_to_and_from_dict_roundtrip(self):
        ev = EvidenceItem(
            id="EVD-001",
            source="HTTP Probe",
            observation="Observed status 200",
            relevant_data="HTTP/1.1 200 OK",
            is_demo_sample=True,
        )
        rem = Remediation(
            tactical="Deny all access to route in reverse proxy config.",
            strategic="Exclude secret files from build pipelines.",
        )
        f = Finding(
            id="GS-SEC-099",
            title="Test Finding Title",
            description="Detailed description exceeding minimum character bounds.",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            affected_asset="https://lab.test/admin",
            evidence=[ev],
            remediation=rem,
            reproduction_steps=["Step 1: Request path", "Step 2: Check status 200"],
        )

        d = f.to_dict()
        self.assertEqual(d["id"], "GS-SEC-099")
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["evidence"][0]["id"], "EVD-001")

        restored = Finding.from_dict(d)
        self.assertEqual(restored.id, f.id)
        self.assertEqual(restored.severity, Severity.HIGH)
        self.assertEqual(restored.evidence[0].id, "EVD-001")
        self.assertEqual(restored.remediation.tactical, rem.tactical)


if __name__ == "__main__":
    unittest.main()
