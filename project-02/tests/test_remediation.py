"""
Tests for RemediationEngine: recommendation synthesis and 3-phase roadmap sequencing.
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
    Remediation,
    Severity,
    Confidence,
)
from gray_sentinel.remediation import RemediationEngine


class TestRemediation(unittest.TestCase):

    def test_remediation_synthesis_headers(self):
        f = Finding(
            id="F01",
            title="Missing Security Headers on Web Service",
            description="HTTP response headers absent from root.",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            affected_asset="https://target/",
        )
        rem = RemediationEngine.ensure_remediation(f)
        self.assertIn("reverse proxy", rem.tactical.lower())
        self.assertIn("ci/cd", rem.strategic.lower())
        self.assertIsNotNone(rem.code_example)

    def test_remediation_synthesis_secret_exposure(self):
        f = Finding(
            id="F02",
            title="Exposed .env Configuration File",
            description="Environment secrets accessible.",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            affected_asset="https://target/.env",
        )
        rem = RemediationEngine.ensure_remediation(f)
        self.assertIn("restrict", rem.tactical.lower())
        self.assertIn("vault", rem.strategic.lower())

    def test_remediation_roadmap_phases(self):
        f_crit = Finding(
            id="F01",
            title="Critical Secrets Exposed",
            description="Desc.",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            affected_asset="target/.env",
        )
        f_med = Finding(
            id="F02",
            title="Exposed Admin Portal",
            description="Desc.",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            affected_asset="target/admin",
        )
        f_low = Finding(
            id="F03",
            title="Missing Headers",
            description="Desc.",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            affected_asset="target/",
        )

        roadmap = RemediationEngine.build_action_roadmap([f_crit, f_med, f_low])
        self.assertEqual(len(roadmap["phase_1_immediate_0_48h"]), 1)
        self.assertEqual(roadmap["phase_1_immediate_0_48h"][0]["id"], "F01")

        self.assertEqual(len(roadmap["phase_2_tactical_3_14d"]), 1)
        self.assertEqual(roadmap["phase_2_tactical_3_14d"][0]["id"], "F02")

        self.assertEqual(len(roadmap["phase_3_strategic_15_30d"]), 1)
        self.assertEqual(roadmap["phase_3_strategic_15_30d"][0]["id"], "F03")


if __name__ == "__main__":
    unittest.main()
