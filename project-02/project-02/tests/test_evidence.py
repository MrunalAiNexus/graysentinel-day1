"""
Tests for EvidenceManager: SHA-256 hashing, secret sanitization, and manifests.
"""

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure src directory is in sys.path
_src = Path(__file__).resolve().parent.parent / "src"
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

from gray_sentinel.models import EvidenceItem
from gray_sentinel.evidence import EvidenceManager
from gray_sentinel.errors import EvidenceIntegrityError


class TestEvidence(unittest.TestCase):

    def test_compute_sha256_success(self):
        content = b"GRAY_SENTINEL_EVIDENCE_SAMPLE_DATA_12345"
        expected_hash = hashlib.sha256(content).hexdigest()

        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            computed = EvidenceManager.compute_sha256(temp_path)
            self.assertEqual(computed, expected_hash)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_compute_sha256_missing_file_raises(self):
        with self.assertRaises(EvidenceIntegrityError):
            EvidenceManager.compute_sha256("/non/existent/evidence/path.png")

    def test_verify_item_integrity(self):
        content = b"VALID_EVIDENCE_PAYLOAD"
        correct_hash = hashlib.sha256(content).hexdigest()

        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            item = EvidenceItem(
                id="EVD-01",
                source="HTTP Log",
                observation="Captured response",
                artifact_path=temp_path,
                sha256_hash=correct_hash,
            )
            is_valid, msg = EvidenceManager.verify_item_integrity(item)
            self.assertTrue(is_valid)
            self.assertTrue(item.verified)

            # Test mismatch
            item.sha256_hash = "deadbeef12345678"
            is_valid_bad, msg_bad = EvidenceManager.verify_item_integrity(item)
            self.assertFalse(is_valid_bad)
            self.assertFalse(item.verified)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_sanitization_redacts_credentials(self):
        dirty_text = "API_KEY=sk-live-abcdef123456; password: 'SuperSecretPassword!'; Bearer eyJhbGciOiJIUz..."
        clean = EvidenceManager.sanitize_evidence_data(dirty_text)
        self.assertNotIn("SuperSecretPassword!", clean)
        self.assertNotIn("sk-live-abcdef123456", clean)
        self.assertIn("[REDACTED_SECRET]", clean)
        self.assertIn("[REDACTED_TOKEN]", clean)

    def test_generate_manifest(self):
        ev1 = EvidenceItem(id="EVD-01", source="Scan", observation="Test", is_demo_sample=True)
        ev2 = EvidenceItem(id="EVD-02", source="Lab Probe", observation="Lab obs", is_demo_sample=False)

        manifest = EvidenceManager.generate_manifest([ev1, ev2])
        self.assertEqual(manifest["evidence_count"], 2)
        self.assertEqual(manifest["demo_sample_count"], 1)
        self.assertEqual(manifest["real_lab_count"], 1)


if __name__ == "__main__":
    unittest.main()
